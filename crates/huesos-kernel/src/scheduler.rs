//! Scheduler v2 kernel integration.
//!
//! Every per-CPU scheduler is single-writer: only its owner CPU mutates its
//! runqueues. Remote wake/kill/policy/spawn/reap requests are published to the
//! generation-tagged task directory and drained from the owner's bitmap inbox.
//! The hot path uses request-based, two-level EEVDF for Job and thread entities;
//! CBS execution is charged from the invariant TSC in nanoseconds.

use crate::task::{Task, TaskKind};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use huesos_arch::{LockRank, RankedIrqSafeTicketLock};
use huesos_lifecycle::{InsertOutcome, TaskGraveyard};
use huesos_object::{KernelObject, Koid, Process};
use huesos_sched::{
    clock::TscClock,
    eevdf::{EevdfKey, EevdfTree, EevdfTreeError},
    job::{JobId, JobState, JobTable},
    task_operations, virtual_delta, AdmissionControl, CbsReservation, CbsRuntime, CpuIndex,
    TaskDirectory, TaskId as V2TaskId, TaskInbox, TaskLocation, TaskSlotAllocator, TaskState,
};
use x86_64::VirtAddr;

/// Maximum number of logical CPUs supported by the kernel scheduler.
pub const MAX_CPUS: usize = huesos_sched::MAX_CPUS;
/// Maximum runnable fair Tasks represented in one per-Job thread tree.
pub const MAX_FAIR_TASKS: usize = 256;
/// Maximum active Job entities on one CPU.
pub const MAX_JOB_QUEUES: usize = 64;
/// Nominal LAPIC timer period in nanoseconds.
pub const TICK_NS: u64 = 10_000_000;
/// Compatibility accounting unit; CPU time is now charged from TSC deltas.
pub const TICK_SERVICE_NS: u64 = TICK_NS;

const FAIR_REQUEST_NS: u64 = 1_000_000;
const JOB_REQUEST_NS: u64 = 4_000_000;
const SLEEP_LAG_DECAY_NS: u64 = 32_000_000;
const MAX_CBS_REFILLS: usize = 8;

static TSC_DEADLINE_ACTIVE: AtomicBool = AtomicBool::new(false);
static MONOTONIC_TICKS: AtomicU64 = AtomicU64::new(0);
static ONLINE_CPUS: [AtomicU64; MAX_CPUS / 64] = [const { AtomicU64::new(0) }; MAX_CPUS / 64];
static NEXT_SPAWN_CPU: AtomicUsize = AtomicUsize::new(0);
static CPU_PENDING_SPAWNS: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(0) }; MAX_CPUS];
static TSC_CLOCK: spin::Once<TscClock> = spin::Once::new();

static TASK_DIRECTORY: TaskDirectory = TaskDirectory::new();
static TASK_SLOTS: TaskSlotAllocator = TaskSlotAllocator::new();
static CPU_INBOX: [TaskInbox; MAX_CPUS] = [const { TaskInbox::new() }; MAX_CPUS];

/// The temporary, pre-owner storage for remote SPAWN operations. The vector is
/// indexed by the global task slot; the target CPU moves a task out before it
/// takes its local scheduler lock.
struct PendingTask {
    id: u64,
    cpu: usize,
    task: Box<Task>,
}
static PENDING_TASKS: RankedIrqSafeTicketLock<Vec<Option<PendingTask>>> =
    RankedIrqSafeTicketLock::new(Vec::new(), LockRank::SCHEDULER);

/// Control-plane policy payloads are separate from the bitmap notification.
static POLICY_REQUESTS: RankedIrqSafeTicketLock<Vec<(u64, SchedPolicy)>> =
    RankedIrqSafeTicketLock::new(Vec::new(), LockRank::SCHEDULER);
static KILL_EXIT_CODES: [AtomicI64; huesos_sched::MAX_TASKS] =
    [const { AtomicI64::new(0) }; huesos_sched::MAX_TASKS];

struct JobIdentityRegistry {
    slots: JobTable,
    koids: [u64; MAX_JOB_QUEUES],
}
impl JobIdentityRegistry {
    const fn new() -> Self {
        Self {
            slots: JobTable::new(),
            koids: [0; MAX_JOB_QUEUES],
        }
    }
}
static JOB_IDENTITIES: RankedIrqSafeTicketLock<JobIdentityRegistry> =
    RankedIrqSafeTicketLock::new(JobIdentityRegistry::new(), LockRank::SCHEDULER);

/// Map an object Job KOID to a stable scheduler Job identity. The root slot is
/// used only when the fixed scheduler Job identity table is exhausted.
pub fn resolve_sched_job_id(koid: Koid) -> JobId {
    if !koid.is_valid() {
        return JobId::ROOT;
    }
    let mut registry = JOB_IDENTITIES.lock();
    if let Some(index) = registry.koids.iter().position(|&known| known == koid.0) {
        return JobId::new(index as u32).map_or(JobId::ROOT, |id| id);
    }
    let Some(slot) = registry.slots.allocate() else {
        return JobId::ROOT;
    };
    let Some(id) = JobId::new(slot.index as u32) else {
        return JobId::ROOT;
    };
    registry.koids[slot.index] = koid.0;
    id
}

/// Set bit N when dense CPU N has completed scheduler initialization.
pub fn mark_cpu_online() {
    let id = cpu_id();
    if id < MAX_CPUS {
        ONLINE_CPUS[id / 64].fetch_or(1u64 << (id % 64), Ordering::SeqCst);
    }
}

/// True when the dense CPU index has an online scheduler.
pub fn is_cpu_online(cpu: usize) -> bool {
    cpu < MAX_CPUS && ONLINE_CPUS[cpu / 64].load(Ordering::SeqCst) & (1u64 << (cpu % 64)) != 0
}

/// Low 64 bits of the online-CPU mask for legacy syscall callers.
pub fn online_cpu_mask() -> u64 {
    ONLINE_CPUS[0].load(Ordering::SeqCst)
}

/// Dense 256-bit mask of online scheduler CPUs.
pub fn online_cpu_mask_words() -> [u64; MAX_CPUS / 64] {
    let mut words = [0; MAX_CPUS / 64];
    for (word, atomic) in words.iter_mut().zip(ONLINE_CPUS.iter()) {
        *word = atomic.load(Ordering::SeqCst);
    }
    words
}

/// Number of online CPUs.
pub fn online_cpu_count() -> usize {
    online_cpu_mask_words()
        .iter()
        .map(|word| word.count_ones() as usize)
        .sum()
}

/// Dense index of the calling CPU.
pub fn current_cpu_index() -> usize {
    cpu_id()
}

/// Number of online CPUs other than the caller.
pub fn online_remote_cpu_count() -> usize {
    online_cpu_count().saturating_sub(1)
}

/// Saved CPU context for a task.
pub type SchedContext = huesos_arch::context_switch::Context;

#[derive(Clone, Copy)]
struct SwitchTarget {
    old: *mut SchedContext,
    new: *const SchedContext,
    new_guards: *mut huesos_sched::ExecutionGuards,
}

struct TaskEnvironment {
    process: Option<Arc<Process>>,
    stack_top: u64,
}

impl TaskEnvironment {
    fn install(self) {
        if self.stack_top != 0 {
            huesos_arch::gdt::set_kernel_stack(VirtAddr::new(self.stack_top));
            huesos_arch::syscall::set_kernel_stack(self.stack_top);
        }
        match self.process {
            Some(process) => huesos_object::set_current_process(process),
            None => huesos_object::clear_current_process(),
        }
    }
}

/// Install the incoming Task's guards and switch stacks. Local interrupts are
/// disabled and both task allocations remain stable for this switch.
fn perform_context_switch(target: SwitchTarget) {
    OBS_CTX_SWITCHES.fetch_add(1, Ordering::Relaxed);
    // SAFETY: Task allocations are stable while schedulable; the scheduler
    // selected `new`, owns its guard state, and disabled local interrupts.
    unsafe {
        huesos_arch::cpu_local::install_execution_guards(target.new_guards);
        huesos_arch::context_switch::context_switch(target.old, target.new);
    }
}

/// Scheduling policy. Fair requests use weighted virtual service; Deadline
/// fields are nanoseconds (capacity, period, current budget, absolute deadline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedPolicy {
    /// Request-based EEVDF policy.
    Fair {
        /// Normalized scheduling weight.
        weight: u64,
    },
    /// Constant-bandwidth server policy.
    Deadline {
        /// Execution capacity in nanoseconds per period.
        capacity: u64,
        /// Reservation period in nanoseconds.
        period: u64,
        /// Remaining budget in nanoseconds.
        remaining_budget: u64,
        /// Absolute TSC-derived deadline in nanoseconds.
        deadline: u64,
    },
}

impl SchedPolicy {
    /// Default nice-zero fair policy.
    pub const fn default_fair() -> Self {
        Self::Fair {
            weight: huesos_sched::NICE_0_WEIGHT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueueKind {
    None,
    Fair,
    Deadline,
    Refill,
}

struct TaskSlot {
    task: Box<Task>,
    request_start: u128,
    request_finish: u128,
    request_remaining_ns: u64,
    blocked_at_ns: u64,
    refill_at_ns: u64,
    queue: QueueKind,
    cbs: Option<CbsRuntime<MAX_CBS_REFILLS>>,
}

struct JobRunqueue {
    id: JobId,
    weight: u64,
    virtual_time: u128,
    threads: EevdfTree<MAX_FAIR_TASKS>,
    fair_runnable: usize,
    root_start: u128,
    root_finish: u128,
    root_remaining_ns: u64,
    root_queued: bool,
    /// CPU-local Job accounting; slot 0 represents this owner CPU.
    accounting: JobState<1>,
}

impl JobRunqueue {
    fn new(id: JobId, weight: u64, virtual_time: u128) -> Option<Self> {
        Some(Self {
            id,
            weight: weight.max(1),
            virtual_time,
            threads: EevdfTree::new(),
            fair_runnable: 0,
            root_start: virtual_time,
            root_finish: virtual_time.saturating_add(
                virtual_delta(JOB_REQUEST_NS, weight.max(1)).map_or(1, |delta| delta),
            ),
            root_remaining_ns: JOB_REQUEST_NS,
            root_queued: false,
            accounting: JobState::new(id, weight.max(1), 0).ok()?,
        })
    }
}

const _: () = assert!(core::mem::size_of::<EevdfTree<MAX_FAIR_TASKS>>() < 256);
const _: () = assert!(core::mem::size_of::<JobRunqueue>() < 256);

struct Scheduler {
    /// Dense CPU index that is the sole writer of all fields below.
    cpu: usize,
    /// Global-slot-indexed local task storage (all live indexes are unique).
    tasks: Vec<Option<TaskSlot>>,
    idle_task: Option<Box<Task>>,
    /// Current global task slot; `None` means this CPU's id-zero idle task.
    current: Option<usize>,
    /// Root Job EEVDF; each entity is one runnable Job, never one Task.
    root_jobs: EevdfTree<MAX_JOB_QUEUES>,
    // EEVDF backing storage is lazily allocated on the heap, keeping each
    // queue descriptor small when ensure_job runs on a task kernel stack.
    job_queues: Vec<JobRunqueue>,
    root_virtual_time: u128,
    root_weight_sum: u64,
    /// EDF queue for runnable CBS Tasks, ordered by absolute deadline.
    deadline_queue: EevdfTree<MAX_FAIR_TASKS>,
    /// CBS replenishment queue, ordered by the next legally eligible time.
    refill_queue: EevdfTree<MAX_FAIR_TASKS>,
    ready_count: usize,
    task_count: usize,
    ticks: u64,
    last_account_ns: u64,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            cpu: 0,
            tasks: Vec::new(),
            idle_task: None,
            current: None,
            root_jobs: EevdfTree::new(),
            job_queues: Vec::new(),
            root_virtual_time: 0,
            root_weight_sum: 0,
            deadline_queue: EevdfTree::new(),
            refill_queue: EevdfTree::new(),
            ready_count: 0,
            task_count: 0,
            ticks: 0,
            last_account_ns: 0,
        }
    }

    fn assert_owner(&self) {
        if self.cpu != cpu_id() {
            scheduler_fail_stop();
        }
    }

    fn job_index(&self, id: JobId) -> Option<usize> {
        self.job_queues.iter().position(|queue| queue.id == id)
    }

    fn ensure_job(&mut self, id: JobId) -> Option<usize> {
        if let Some(index) = self.job_index(id) {
            return Some(index);
        }
        if self.job_queues.len() >= MAX_JOB_QUEUES {
            return None;
        }
        if self.job_queues.try_reserve(1).is_err() {
            return None;
        }
        let queue = JobRunqueue::new(id, huesos_sched::NICE_0_WEIGHT, self.root_virtual_time)?;
        self.job_queues.push(queue);
        Some(self.job_queues.len() - 1)
    }

    fn task(&self, slot: usize) -> Option<&TaskSlot> {
        self.tasks.get(slot)?.as_ref()
    }

    fn task_mut(&mut self, slot: usize) -> Option<&mut TaskSlot> {
        self.tasks.get_mut(slot)?.as_mut()
    }

    fn task_matches(&self, id: u64) -> bool {
        let Some(location) = task_location(id) else {
            return false;
        };
        location.owner.as_usize() == self.cpu
            && location.local_index as usize
                == V2TaskId::from_raw(id).map_or(usize::MAX, |v| v.slot())
            && self
                .task(location.local_index as usize)
                .is_some_and(|slot| slot.task.id == id)
    }

    fn weight(policy: SchedPolicy) -> u64 {
        match policy {
            SchedPolicy::Fair { weight } => weight.max(1),
            SchedPolicy::Deadline { .. } => huesos_sched::NICE_0_WEIGHT,
        }
    }

    fn policy_is_fair(policy: SchedPolicy) -> bool {
        matches!(policy, SchedPolicy::Fair { .. })
    }

    fn insert_root_job(&mut self, index: usize) {
        let queue = &mut self.job_queues[index];
        if queue.root_queued || queue.fair_runnable == 0 {
            return;
        }
        let key = EevdfKey {
            virtual_start: queue.root_start,
            task_id: u64::from(queue.id.raw()),
        };
        match self.root_jobs.insert(key, queue.root_finish) {
            Ok(()) => queue.root_queued = true,
            Err(EevdfTreeError::Full) => scheduler_fail_stop(),
            Err(_) => scheduler_fail_stop(),
        }
    }

    fn remove_root_job(&mut self, index: usize) {
        let queue = &mut self.job_queues[index];
        if !queue.root_queued {
            return;
        }
        let key = EevdfKey {
            virtual_start: queue.root_start,
            task_id: u64::from(queue.id.raw()),
        };
        if self.root_jobs.remove(key).is_err() {
            scheduler_fail_stop();
        }
        queue.root_queued = false;
    }

    fn update_fair_population(&mut self, job_id: JobId, delta: isize) {
        let Some(index) = self.job_index(job_id) else {
            scheduler_fail_stop();
        };
        let before = self.job_queues[index].fair_runnable;
        if delta > 0 {
            self.job_queues[index].fair_runnable = self.job_queues[index]
                .fair_runnable
                .saturating_add(delta as usize);
        } else {
            self.job_queues[index].fair_runnable = self.job_queues[index]
                .fair_runnable
                .saturating_sub(delta.unsigned_abs());
        }
        let after = self.job_queues[index].fair_runnable;
        if before == 0 && after != 0 {
            self.root_weight_sum = self
                .root_weight_sum
                .saturating_add(self.job_queues[index].weight);
        } else if before != 0 && after == 0 {
            self.root_weight_sum = self
                .root_weight_sum
                .saturating_sub(self.job_queues[index].weight);
            self.remove_root_job(index);
        }
        if after != 0 {
            self.insert_root_job(index);
        }
    }

    fn make_request(start: u128, duration_ns: u64, weight: u64) -> (u128, u64) {
        let delta = virtual_delta(duration_ns, weight.max(1)).map_or(1, |delta| delta);
        (start.saturating_add(delta), duration_ns)
    }

    fn insert_fair_tree(&mut self, slot_index: usize) {
        let Some(slot) = self.task(slot_index) else {
            scheduler_fail_stop();
        };
        let id = slot.task.id;
        let job_id = slot.task.job_id;
        let start = slot.request_start;
        let finish = slot.request_finish;
        let Some(job_index) = self.job_index(job_id) else {
            scheduler_fail_stop();
        };
        let key = EevdfKey {
            virtual_start: start,
            task_id: id,
        };
        match self.job_queues[job_index].threads.insert(key, finish) {
            Ok(()) => {}
            Err(EevdfTreeError::Full) => scheduler_fail_stop(),
            Err(_) => scheduler_fail_stop(),
        }
        if let Some(task) = self.task_mut(slot_index) {
            task.queue = QueueKind::Fair;
        }
        self.ready_count = self.ready_count.saturating_add(1);
        self.insert_root_job(job_index);
    }

    fn insert_deadline_tree(&mut self, slot_index: usize) {
        let Some(slot) = self.task(slot_index) else {
            scheduler_fail_stop();
        };
        let Some(runtime) = slot.cbs else {
            scheduler_fail_stop();
        };
        let id = slot.task.id;
        let deadline = runtime.absolute_deadline_ns();
        let key = EevdfKey {
            virtual_start: u128::from(deadline),
            task_id: id,
        };
        match self.deadline_queue.insert(key, u128::from(deadline)) {
            Ok(()) => {}
            Err(EevdfTreeError::Full) => scheduler_fail_stop(),
            Err(_) => scheduler_fail_stop(),
        }
        if let Some(task) = self.task_mut(slot_index) {
            task.queue = QueueKind::Deadline;
            if let SchedPolicy::Deadline {
                capacity, period, ..
            } = task.task.sched_policy
            {
                task.task.sched_policy = SchedPolicy::Deadline {
                    capacity,
                    period,
                    remaining_budget: runtime.remaining_ns(),
                    deadline,
                };
            }
        }
        self.ready_count = self.ready_count.saturating_add(1);
    }

    fn insert_refill_tree(&mut self, slot_index: usize) {
        let Some(slot) = self.task(slot_index) else {
            scheduler_fail_stop();
        };
        let Some(runtime) = slot.cbs else {
            scheduler_fail_stop();
        };
        let Some(eligible) = runtime.refills().next_eligible() else {
            if let Some(task) = self.task_mut(slot_index) {
                task.queue = QueueKind::None;
            }
            return;
        };
        let id = slot.task.id;
        let key = EevdfKey {
            virtual_start: u128::from(eligible),
            task_id: id,
        };
        match self.refill_queue.insert(key, u128::from(eligible)) {
            Ok(()) => {}
            Err(EevdfTreeError::Full) => scheduler_fail_stop(),
            Err(_) => scheduler_fail_stop(),
        }
        if let Some(task) = self.task_mut(slot_index) {
            task.queue = QueueKind::Refill;
            task.refill_at_ns = eligible;
        }
    }

    fn remove_task_queue(&mut self, slot_index: usize) {
        let Some(slot) = self.task(slot_index) else {
            return;
        };
        let queue = slot.queue;
        let id = slot.task.id;
        let job_id = slot.task.job_id;
        let start = slot.request_start;
        let deadline = slot.cbs.map_or(0, CbsRuntime::absolute_deadline_ns);
        let refill_at = slot.refill_at_ns;
        match queue {
            QueueKind::None => return,
            QueueKind::Fair => {
                let Some(job_index) = self.job_index(job_id) else {
                    scheduler_fail_stop();
                };
                if self.job_queues[job_index]
                    .threads
                    .remove(EevdfKey {
                        virtual_start: start,
                        task_id: id,
                    })
                    .is_err()
                {
                    scheduler_fail_stop();
                }
                self.ready_count = self.ready_count.saturating_sub(1);
            }
            QueueKind::Deadline => {
                if self
                    .deadline_queue
                    .remove(EevdfKey {
                        virtual_start: u128::from(deadline),
                        task_id: id,
                    })
                    .is_err()
                {
                    scheduler_fail_stop();
                }
                self.ready_count = self.ready_count.saturating_sub(1);
            }
            QueueKind::Refill => {
                if self
                    .refill_queue
                    .remove(EevdfKey {
                        virtual_start: u128::from(refill_at),
                        task_id: id,
                    })
                    .is_err()
                {
                    scheduler_fail_stop();
                }
            }
        }
        if let Some(task) = self.task_mut(slot_index) {
            task.queue = QueueKind::None;
        }
    }

    fn create_cbs(policy: SchedPolicy, now_ns: u64) -> Option<CbsRuntime<MAX_CBS_REFILLS>> {
        let SchedPolicy::Deadline {
            capacity, period, ..
        } = policy
        else {
            return None;
        };
        let reservation = CbsReservation::new(capacity, period, period).ok()?;
        CbsRuntime::new(reservation, now_ns).ok()
    }

    fn insert_task(&mut self, cpu: usize, task: Box<Task>, now_ns: u64) -> Result<(), Box<Task>> {
        self.assert_owner();
        let Some(id) = V2TaskId::from_raw(task.id) else {
            return Err(task);
        };
        if id.slot() >= huesos_sched::MAX_TASKS
            || self.task(id.slot()).is_some()
            || !matches!(task.kind, TaskKind::Kernel | TaskKind::User { .. })
        {
            return Err(task);
        }
        let Some(cpu_id) = CpuIndex::new(cpu) else {
            return Err(task);
        };
        let policy = task.sched_policy;
        let job_id = task.job_id;
        let task_weight = Self::weight(policy);
        let fair = Self::policy_is_fair(policy);
        let cbs = if fair {
            None
        } else {
            let Some(runtime) = Self::create_cbs(policy, now_ns) else {
                return Err(task);
            };
            Some(runtime)
        };
        let Some(job_index) = self.ensure_job(job_id) else {
            return Err(task);
        };
        if fair && self.job_queues[job_index].threads.is_full() {
            return Err(task);
        }
        if !fair && self.deadline_queue.is_full() {
            return Err(task);
        }
        if fair
            && self.job_queues[job_index].fair_runnable == 0
            && !self.job_queues[job_index].root_queued
            && self.root_jobs.is_full()
        {
            return Err(task);
        }
        if self.tasks.len() <= id.slot() {
            if self
                .tasks
                .try_reserve(id.slot() + 1 - self.tasks.len())
                .is_err()
            {
                return Err(task);
            }
            self.tasks.resize_with(id.slot() + 1, || None);
        }

        let mut task = task;
        if task.lifecycle.defer_ready(cpu_id).is_err()
            || task.lifecycle.enqueue_ready(cpu_id).is_err()
        {
            scheduler_fail_stop();
        }
        let (request_start, request_finish, request_remaining) = if fair {
            let vtime = self.job_queues[job_index].virtual_time;
            let initial_slice = (FAIR_REQUEST_NS / 2).max(1);
            let credit = virtual_delta(initial_slice, task_weight).unwrap_or(1);
            let start = vtime.saturating_sub(credit);
            let (finish, request) = Self::make_request(start, initial_slice, task_weight);
            (start, finish, request)
        } else {
            (0, 0, 0)
        };
        let slot_index = id.slot();
        self.tasks[slot_index] = Some(TaskSlot {
            task,
            request_start,
            request_finish,
            request_remaining_ns: request_remaining,
            blocked_at_ns: now_ns,
            refill_at_ns: 0,
            queue: QueueKind::None,
            cbs,
        });
        if self.job_queues[job_index]
            .accounting
            .thread_ready(0, task_weight)
            .is_err()
        {
            scheduler_fail_stop();
        }
        if fair {
            self.update_fair_population(job_id, 1);
            self.insert_fair_tree(slot_index);
        } else {
            self.insert_deadline_tree(slot_index);
        }
        self.task_count = self.task_count.saturating_add(1);
        record_task(
            slot_index,
            self.task(slot_index).map(|slot| &*slot.task),
            cpu,
            1,
        );
        publish_cpu_stats(self);
        if self.should_preempt_current(slot_index) && cpu == self::cpu_id() {
            huesos_arch::preemption::request_reschedule();
        }
        Ok(())
    }

    fn account_running(&mut self, now_ns: u64) -> Option<Arc<Process>> {
        let elapsed_ns = now_ns.saturating_sub(self.last_account_ns);
        self.last_account_ns = now_ns;
        let slot_index = self.current?;
        let Some(task) = self.task(slot_index) else {
            scheduler_fail_stop();
        };
        let task_id = task.task.id;
        let job_id = task.task.job_id;
        let policy = task.task.sched_policy;
        let user_process = match &task.task.kind {
            TaskKind::User { process, .. } => Some(Arc::clone(process)),
            TaskKind::Kernel | TaskKind::Reaped => None,
        };
        if elapsed_ns == 0 {
            return user_process;
        }
        let Some(job_index) = self.job_index(job_id) else {
            scheduler_fail_stop();
        };
        if self.job_queues[job_index]
            .accounting
            .charge(0, elapsed_ns)
            .is_err()
        {
            scheduler_fail_stop();
        }
        let _ = self.job_queues[job_index]
            .accounting
            .maybe_replenish(now_ns);

        match policy {
            SchedPolicy::Fair { weight } => {
                let total_weight = self.job_queues[job_index].accounting.per_cpu[0]
                    .demand_weight
                    .max(1);
                self.job_queues[job_index].virtual_time =
                    self.job_queues[job_index].virtual_time.saturating_add(
                        virtual_delta(elapsed_ns, total_weight).map_or(1, |delta| delta),
                    );
                if self.root_weight_sum != 0 {
                    self.root_virtual_time = self.root_virtual_time.saturating_add(
                        virtual_delta(elapsed_ns, self.root_weight_sum).map_or(1, |delta| delta),
                    );
                }
                if let Some(slot) = self.task_mut(slot_index) {
                    let w = weight.max(1);
                    let mut remaining = elapsed_ns;
                    while remaining != 0 {
                        if remaining < slot.request_remaining_ns {
                            let delta = virtual_delta(remaining, w).unwrap_or(1);
                            slot.request_remaining_ns -= remaining;
                            slot.request_start = slot
                                .request_start
                                .saturating_add(delta)
                                .min(slot.request_finish);
                            let (finish, _) = Self::make_request(
                                slot.request_start,
                                slot.request_remaining_ns,
                                w,
                            );
                            slot.request_finish = finish;
                            remaining = 0;
                        } else {
                            remaining -= slot.request_remaining_ns;
                            slot.request_start = slot.request_finish;
                            let (finish, request) =
                                Self::make_request(slot.request_start, FAIR_REQUEST_NS, w);
                            slot.request_finish = finish;
                            slot.request_remaining_ns = request;
                        }
                    }
                }
                let was_root_queued = self.job_queues[job_index].root_queued;
                if was_root_queued {
                    self.remove_root_job(job_index);
                }
                {
                    let job = &mut self.job_queues[job_index];
                    let jw = job.weight.max(1);
                    let mut remaining = elapsed_ns;
                    while remaining != 0 {
                        if remaining < job.root_remaining_ns {
                            let delta = virtual_delta(remaining, jw).unwrap_or(1);
                            job.root_remaining_ns -= remaining;
                            job.root_start =
                                job.root_start.saturating_add(delta).min(job.root_finish);
                            job.root_finish = job.root_start.saturating_add(
                                virtual_delta(job.root_remaining_ns, jw).unwrap_or(1),
                            );
                            remaining = 0;
                        } else {
                            remaining -= job.root_remaining_ns;
                            job.root_start = job.root_finish;
                            job.root_finish = job
                                .root_start
                                .saturating_add(virtual_delta(JOB_REQUEST_NS, jw).unwrap_or(1));
                            job.root_remaining_ns = JOB_REQUEST_NS;
                        }
                    }
                }
                if was_root_queued && self.job_queues[job_index].fair_runnable != 0 {
                    self.insert_root_job(job_index);
                }
            }
            SchedPolicy::Deadline { .. } => {
                if let Some(slot) = self.task_mut(slot_index) {
                    if let Some(runtime) = slot.cbs.as_mut() {
                        let charge = elapsed_ns.min(runtime.remaining_ns());
                        let start = now_ns.saturating_sub(elapsed_ns);
                        if runtime.charge(start, charge).is_err() {
                            scheduler_fail_stop();
                        }
                        if let SchedPolicy::Deadline {
                            capacity, period, ..
                        } = slot.task.sched_policy
                        {
                            slot.task.sched_policy = SchedPolicy::Deadline {
                                capacity,
                                period,
                                remaining_budget: runtime.remaining_ns(),
                                deadline: runtime.absolute_deadline_ns(),
                            };
                        }
                    }
                }
            }
        }
        let _ = task_id;
        user_process
    }

    fn enqueue_refill_or_deadline(&mut self, slot_index: usize) {
        let runnable = self
            .task(slot_index)
            .and_then(|slot| slot.cbs)
            .is_some_and(CbsRuntime::runnable);
        if runnable {
            self.insert_deadline_tree(slot_index);
        } else {
            self.insert_refill_tree(slot_index);
        }
    }

    fn replenish_due(&mut self, now_ns: u64) {
        while let Some(key) = self.refill_queue.peek_min() {
            if key.virtual_start > u128::from(now_ns) {
                break;
            }
            let popped = match self.refill_queue.pop_min() {
                Ok(Some(key)) => key,
                Ok(None) => break,
                Err(_) => scheduler_fail_stop(),
            };
            let Some(id) = V2TaskId::from_raw(popped.task_id) else {
                continue;
            };
            let slot_index = id.slot();
            let Some(slot) = self.task_mut(slot_index) else {
                continue;
            };
            if slot.task.id != popped.task_id || slot.queue != QueueKind::Refill {
                continue;
            }
            slot.queue = QueueKind::None;
            let Some(runtime) = slot.cbs.as_mut() else {
                scheduler_fail_stop();
            };
            if runtime.replenish(now_ns).is_err() {
                scheduler_fail_stop();
            }
            if let SchedPolicy::Deadline {
                capacity, period, ..
            } = slot.task.sched_policy
            {
                slot.task.sched_policy = SchedPolicy::Deadline {
                    capacity,
                    period,
                    remaining_budget: runtime.remaining_ns(),
                    deadline: runtime.absolute_deadline_ns(),
                };
            }
            self.enqueue_refill_or_deadline(slot_index);
        }
    }

    fn pick_next(&mut self, now_ns: u64) -> Option<usize> {
        self.replenish_due(now_ns);
        loop {
            let key = match self.deadline_queue.pop_min() {
                Ok(Some(key)) => key,
                Ok(None) => break,
                Err(_) => scheduler_fail_stop(),
            };
            let Some(id) = V2TaskId::from_raw(key.task_id) else {
                continue;
            };
            let slot_index = id.slot();
            let valid = self.task(slot_index).is_some_and(|slot| {
                slot.task.id == key.task_id && slot.queue == QueueKind::Deadline
            });
            if !valid {
                continue;
            }
            if let Some(slot) = self.task_mut(slot_index) {
                slot.queue = QueueKind::None;
            }
            self.ready_count = self.ready_count.saturating_sub(1);
            return Some(slot_index);
        }
        loop {
            let (key, _finish) = match self.root_jobs.pop_eligible(&mut self.root_virtual_time) {
                Ok(Some(item)) => item,
                Ok(None) => break,
                Err(_) => scheduler_fail_stop(),
            };
            let raw_job = match u32::try_from(key.task_id) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let Some(job_id) = JobId::new(raw_job) else {
                if raw_job != 0 {
                    continue;
                }
                // JobId::ROOT is a valid entity even though `new(0)` reserves
                // zero; locate it explicitly.
                let Some(root_index) = self.job_index(JobId::ROOT) else {
                    continue;
                };
                self.job_queues[root_index].root_queued = false;
                let popped = self.pop_job_thread(root_index);
                if !self.job_queues[root_index].threads.is_empty()
                    && self.job_queues[root_index].fair_runnable != 0
                {
                    self.insert_root_job(root_index);
                }
                if let Some(slot) = popped {
                    return Some(slot);
                }
                continue;
            };
            let Some(job_index) = self.job_index(job_id) else {
                continue;
            };
            self.job_queues[job_index].root_queued = false;
            let popped = self.pop_job_thread(job_index);
            if !self.job_queues[job_index].threads.is_empty()
                && self.job_queues[job_index].fair_runnable != 0
            {
                self.insert_root_job(job_index);
            }
            if let Some(slot) = popped {
                return Some(slot);
            }
        }
        None
    }

    fn pop_job_thread(&mut self, job_index: usize) -> Option<usize> {
        let job_queue = &mut self.job_queues[job_index];
        let key = match job_queue.threads.pop_eligible(&mut job_queue.virtual_time) {
            Ok(Some((key, _finish))) => key,
            Ok(None) => return None,
            Err(_) => scheduler_fail_stop(),
        };
        let id = V2TaskId::from_raw(key.task_id)?;
        let slot_index = id.slot();
        let valid = self
            .task(slot_index)
            .is_some_and(|slot| slot.task.id == key.task_id && slot.queue == QueueKind::Fair);
        if !valid {
            return None;
        }
        if let Some(slot) = self.task_mut(slot_index) {
            slot.queue = QueueKind::None;
        }
        self.ready_count = self.ready_count.saturating_sub(1);
        Some(slot_index)
    }

    fn requeue_current(&mut self, slot_index: usize) {
        let Some(state) = self
            .task(slot_index)
            .map(|slot| slot.task.lifecycle.state())
        else {
            return;
        };
        if state == TaskState::Running {
            let Some(cpu) = CpuIndex::new(self.cpu) else {
                scheduler_fail_stop();
            };
            if let Some(slot) = self.task_mut(slot_index) {
                if slot.task.lifecycle.preempt(cpu).is_err() {
                    scheduler_fail_stop();
                }
            }
        } else if state != TaskState::Ready {
            return;
        }
        let policy = match self.task(slot_index) {
            Some(slot) => slot.task.sched_policy,
            None => return,
        };
        match policy {
            SchedPolicy::Fair { .. } => self.insert_fair_tree(slot_index),
            SchedPolicy::Deadline { .. } => self.enqueue_refill_or_deadline(slot_index),
        }
        record_task(
            slot_index,
            self.task(slot_index).map(|slot| &*slot.task),
            self.cpu,
            1,
        );
    }

    fn tick_without_preempt(&mut self, now_ns: u64) -> Option<Arc<Process>> {
        self.assert_owner();
        self.ticks = self.ticks.saturating_add(1);
        let charge_process = self.account_running(now_ns);
        self.replenish_due(now_ns);
        publish_cpu_stats(self);
        charge_process
    }

    fn schedule(&mut self, now_ns: u64, hardware_tick: bool) -> ScheduleResult {
        self.assert_owner();
        if hardware_tick {
            self.ticks = self.ticks.saturating_add(1);
        }
        let old_current = self.current;
        let charge_process = self.account_running(now_ns);
        if let Some(old_slot) = old_current {
            let finished = self.task(old_slot).is_none_or(|slot| {
                slot.task.finished.load(Ordering::Acquire)
                    || matches!(
                        slot.task.lifecycle.state(),
                        TaskState::Dead | TaskState::Reaped
                    )
            });
            let blocked = self.task(old_slot).is_some_and(|slot| {
                slot.task.blocked.load(Ordering::Acquire)
                    || slot.task.lifecycle.state() == TaskState::Blocked
            });
            if finished {
                if let Some(slot) = self.task(old_slot) {
                    enqueue_reap(slot.task.id);
                }
            } else if !blocked {
                self.requeue_current(old_slot);
            }
        }
        let next = self.pick_next(now_ns);
        self.current = next;
        if let Some(slot_index) = next {
            let Some(cpu) = CpuIndex::new(self.cpu) else {
                scheduler_fail_stop();
            };
            if let Some(slot) = self.task_mut(slot_index) {
                if slot.task.lifecycle.state() == TaskState::Ready
                    && slot.task.lifecycle.start_running(cpu).is_err()
                {
                    scheduler_fail_stop();
                }
                slot.task.blocked.store(false, Ordering::Release);
                slot.task.wake_pending.store(false, Ordering::Release);
            }
            record_task(
                slot_index,
                self.task(slot_index).map(|slot| &*slot.task),
                self.cpu,
                0,
            );
        }
        let current_id = self
            .current
            .and_then(|slot| self.task(slot).map(|task| task.task.id))
            .map_or(0, |id| id);
        let current_process = self
            .current
            .and_then(|slot| self.task(slot))
            .and_then(|slot| match &slot.task.kind {
                TaskKind::User { process, .. } => Some(process.koid().0),
                TaskKind::Kernel | TaskKind::Reaped => None,
            })
            .map_or(0, |koid| koid);
        CURRENT_TASK_IDS[self.cpu].store(current_id, Ordering::Release);
        CURRENT_PROCESS_KOIDS[self.cpu].store(current_process, Ordering::Release);
        let decision = if old_current == next {
            None
        } else {
            self.make_switch_target(old_current, next)
        };
        publish_cpu_stats(self);
        ScheduleResult {
            decision,
            charge_process,
        }
    }

    fn make_switch_target(
        &mut self,
        old: Option<usize>,
        new: Option<usize>,
    ) -> Option<SwitchDecision> {
        let idle = self.idle_task.as_mut()?;
        let old_context = match old {
            Some(index) => &raw mut self.tasks.get_mut(index)?.as_mut()?.task.context,
            None => &raw mut idle.context,
        };
        let (new_context, new_guards, environment) = match new {
            Some(index) => {
                let (process, stack_top) = {
                    let task = &self.tasks.get(index)?.as_ref()?.task;
                    let process = match &task.kind {
                        TaskKind::User { process, .. } => Some(Arc::clone(process)),
                        TaskKind::Kernel | TaskKind::Reaped => None,
                    };
                    (process, task.kernel_stack_top())
                };
                let new_context = &raw const self.tasks.get(index)?.as_ref()?.task.context;
                let new_guards =
                    &raw mut self.tasks.get_mut(index)?.as_mut()?.task.execution_guards;
                (
                    new_context,
                    new_guards,
                    TaskEnvironment { process, stack_top },
                )
            }
            None => (
                &raw const idle.context,
                &raw mut idle.execution_guards,
                TaskEnvironment {
                    process: None,
                    stack_top: idle.kernel_stack_top(),
                },
            ),
        };
        Some(SwitchDecision {
            target: SwitchTarget {
                old: old_context,
                new: new_context,
                new_guards,
            },
            environment,
        })
    }

    fn block_current(&mut self, now_ns: u64) {
        self.assert_owner();
        let Some(slot_index) = self.current else {
            return;
        };
        let _ = self.account_running(now_ns);
        let Some(cpu) = CpuIndex::new(self.cpu) else {
            scheduler_fail_stop();
        };
        let (parked, job_id, weight, is_fair) = {
            let Some(slot) = self.task_mut(slot_index) else {
                scheduler_fail_stop();
            };
            let previous_epoch = match slot.task.wait_epoch.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |epoch| epoch.checked_add(1),
            ) {
                Ok(epoch) => epoch,
                Err(_) => scheduler_fail_stop(),
            };
            let epoch = previous_epoch + 1;
            if slot.task.lifecycle.begin_block(cpu, epoch).is_err() {
                scheduler_fail_stop();
            }
            slot.task.blocked.store(true, Ordering::Release);
            let pending_wake = slot.task.wake_pending.swap(false, Ordering::AcqRel);
            if pending_wake && slot.task.lifecycle.wake(cpu, epoch).is_err() {
                scheduler_fail_stop();
            }
            let parked = match slot.task.lifecycle.complete_block(cpu, epoch) {
                Ok(parked) => parked,
                Err(_) => scheduler_fail_stop(),
            };
            if !parked {
                if slot.task.lifecycle.complete_wake(cpu, epoch).is_err() {
                    scheduler_fail_stop();
                }
                slot.task.blocked.store(false, Ordering::Release);
                slot.task.wake_pending.store(false, Ordering::Release);
            } else {
                slot.blocked_at_ns = now_ns;
            }
            (
                parked,
                slot.task.job_id,
                Self::weight(slot.task.sched_policy),
                Self::policy_is_fair(slot.task.sched_policy),
            )
        };
        if !parked {
            record_task(
                slot_index,
                self.task(slot_index).map(|slot| &*slot.task),
                self.cpu,
                1,
            );
            return;
        }
        let Some(job_index) = self.job_index(job_id) else {
            scheduler_fail_stop();
        };
        if self.job_queues[job_index]
            .accounting
            .thread_blocked(0, weight)
            .is_err()
        {
            scheduler_fail_stop();
        }
        if is_fair {
            self.update_fair_population(job_id, -1);
        }
        record_task(
            slot_index,
            self.task(slot_index).map(|slot| &*slot.task),
            self.cpu,
            2,
        );
    }

    fn apply_wake(&mut self, id: u64, slot_index: usize, now_ns: u64) {
        self.assert_owner();
        if !self.task_matches(id) {
            return;
        }
        let Some(cpu) = CpuIndex::new(self.cpu) else {
            scheduler_fail_stop();
        };
        let state = self
            .task(slot_index)
            .map(|slot| slot.task.lifecycle.state());
        match state {
            Some(TaskState::Running | TaskState::Blocking) => {
                if let Some(slot) = self.task_mut(slot_index) {
                    slot.task.wake_pending.store(true, Ordering::Release);
                    if slot.task.lifecycle.state() == TaskState::Blocking {
                        let epoch = slot.task.wait_epoch.load(Ordering::Acquire);
                        let _ = slot.task.lifecycle.wake(cpu, epoch);
                    }
                }
                return;
            }
            Some(TaskState::Blocked) => {}
            _ => return,
        }
        let epoch = self
            .task(slot_index)
            .map_or(0, |slot| slot.task.wait_epoch.load(Ordering::Acquire));
        if let Some(slot) = self.task_mut(slot_index) {
            if slot.task.lifecycle.wake(cpu, epoch).is_err()
                || slot.task.lifecycle.complete_wake(cpu, epoch).is_err()
            {
                return;
            }
            slot.task.blocked.store(false, Ordering::Release);
            slot.task.wake_pending.store(false, Ordering::Release);
        }
        let Some((job_id, weight, policy, blocked_at)) = self.task(slot_index).map(|slot| {
            (
                slot.task.job_id,
                Self::weight(slot.task.sched_policy),
                slot.task.sched_policy,
                slot.blocked_at_ns,
            )
        }) else {
            return;
        };
        let Some(job_index) = self.ensure_job(job_id) else {
            scheduler_fail_stop();
        };
        if self.job_queues[job_index]
            .accounting
            .thread_ready(0, weight)
            .is_err()
        {
            scheduler_fail_stop();
        }
        if Self::policy_is_fair(policy) {
            self.update_fair_population(job_id, 1);
            self.place_wake_request(slot_index, now_ns.saturating_sub(blocked_at));
            self.insert_fair_tree(slot_index);
        } else {
            if let Some(slot) = self.task_mut(slot_index) {
                if let Some(runtime) = slot.cbs.as_mut() {
                    if runtime.replenish(now_ns).is_err() {
                        scheduler_fail_stop();
                    }
                }
            }
            self.enqueue_refill_or_deadline(slot_index);
        }
        record_task(
            slot_index,
            self.task(slot_index).map(|slot| &*slot.task),
            self.cpu,
            1,
        );
        publish_cpu_stats(self);
        if self.should_preempt_current(slot_index) && self.cpu == cpu_id() {
            huesos_arch::preemption::request_reschedule();
        }
    }

    fn should_preempt_current(&self, candidate_slot: usize) -> bool {
        let Some(current_slot) = self.current else {
            return true;
        };
        if current_slot == candidate_slot {
            return false;
        }
        let Some(candidate) = self.task(candidate_slot) else {
            return false;
        };
        let Some(current) = self.task(current_slot) else {
            return true;
        };
        match (
            candidate.queue,
            Self::policy_is_fair(current.task.sched_policy),
        ) {
            (QueueKind::Deadline, true) => true,
            (QueueKind::Deadline, false) => {
                let cand_dl = candidate
                    .cbs
                    .map_or(u64::MAX, CbsRuntime::absolute_deadline_ns);
                let cur_dl = current
                    .cbs
                    .map_or(u64::MAX, CbsRuntime::absolute_deadline_ns);
                cand_dl < cur_dl
            }
            (QueueKind::Fair, true) => {
                let Some(cand_job_idx) = self.job_index(candidate.task.job_id) else {
                    return false;
                };
                let cand_job = &self.job_queues[cand_job_idx];
                if candidate.request_start > cand_job.virtual_time {
                    return false;
                }
                if candidate.task.job_id == current.task.job_id {
                    candidate.request_finish < current.request_finish
                } else {
                    let Some(cur_job_idx) = self.job_index(current.task.job_id) else {
                        return false;
                    };
                    let cur_job = &self.job_queues[cur_job_idx];
                    cand_job.root_start <= self.root_virtual_time
                        && cand_job.root_finish < cur_job.root_finish
                }
            }
            _ => false,
        }
    }

    fn place_wake_request(&mut self, slot_index: usize, sleep_ns: u64) {
        let Some((job_id, weight, old_start, old_finish)) = self.task(slot_index).map(|slot| {
            let weight = match slot.task.sched_policy {
                SchedPolicy::Fair { weight } => weight.max(1),
                SchedPolicy::Deadline { .. } => 1,
            };
            (
                slot.task.job_id,
                weight,
                slot.request_start,
                slot.request_finish,
            )
        }) else {
            return;
        };
        let Some(job_index) = self.job_index(job_id) else {
            scheduler_fail_stop();
        };
        let vtime = self.job_queues[job_index].virtual_time;
        let old_lag = signed_delta(vtime, old_start);
        let bounded = bound_lag(
            old_lag,
            virtual_delta(FAIR_REQUEST_NS.saturating_mul(4), weight).map_or(1, |delta| delta),
        );
        let decay = SLEEP_LAG_DECAY_NS
            .saturating_sub(sleep_ns)
            .min(SLEEP_LAG_DECAY_NS);
        let lag = bounded.saturating_mul(i128::from(decay)) / i128::from(SLEEP_LAG_DECAY_NS.max(1));
        let start = signed_subtract(vtime, lag);
        let (finish, remaining) = Self::make_request(start, FAIR_REQUEST_NS, weight);
        if let Some(slot) = self.task_mut(slot_index) {
            slot.request_start = start;
            slot.request_finish = finish.max(old_finish.min(start));
            slot.request_remaining_ns = remaining;
        }
    }

    fn mark_dead(&mut self, id: u64, slot_index: usize, exit_code: i64, now_ns: u64) {
        self.assert_owner();
        let cpu = self.cpu;
        if !self.task_matches(id) {
            return;
        }
        if self.current == Some(slot_index) {
            let _ = self.account_running(now_ns);
        }
        let state = self
            .task(slot_index)
            .map(|slot| slot.task.lifecycle.state());
        if matches!(state, Some(TaskState::Dead | TaskState::Reaped)) {
            return;
        }
        let queue_kind = self
            .task(slot_index)
            .map_or(QueueKind::None, |slot| slot.queue);
        let job_id = self
            .task(slot_index)
            .map_or(JobId::ROOT, |slot| slot.task.job_id);
        let policy = self
            .task(slot_index)
            .map_or(SchedPolicy::default_fair(), |slot| slot.task.sched_policy);
        let weight = Self::weight(policy);
        let was_runnable = matches!(state, Some(TaskState::Ready | TaskState::Running))
            && !matches!(queue_kind, QueueKind::Refill);
        if queue_kind != QueueKind::None {
            self.remove_task_queue(slot_index);
        }
        if was_runnable {
            if let Some(job_index) = self.job_index(job_id) {
                if self.job_queues[job_index]
                    .accounting
                    .thread_blocked(0, weight)
                    .is_err()
                {
                    scheduler_fail_stop();
                }
            }
        }
        if Self::policy_is_fair(policy) && was_runnable {
            self.update_fair_population(job_id, -1);
        }
        let Some(slot) = self.task_mut(slot_index) else {
            return;
        };
        let lifecycle_state = slot.task.lifecycle.state();
        if matches!(
            lifecycle_state,
            TaskState::Ready | TaskState::Running | TaskState::Blocked
        ) && (slot.task.lifecycle.begin_dying().is_err()
            || slot.task.lifecycle.mark_dead().is_err())
        {
            scheduler_fail_stop();
        }
        slot.task.finished.store(true, Ordering::Release);
        slot.task.blocked.store(false, Ordering::Release);
        slot.task.wake_pending.store(false, Ordering::Release);
        let thread = match &slot.task.kind {
            TaskKind::User { thread, .. } => thread.as_ref().map(Arc::clone),
            TaskKind::Kernel | TaskKind::Reaped => None,
        };
        record_task(slot_index, Some(&*slot.task), cpu, 3);
        if let Some(thread) = thread {
            THREAD_EXIT_QUEUE.lock().push((thread, exit_code));
        }
        enqueue_reap(id);
        publish_cpu_stats(self);
    }

    fn apply_policy(&mut self, id: u64, slot_index: usize, policy: SchedPolicy, now_ns: u64) {
        self.assert_owner();
        if !self.task_matches(id) {
            return;
        }
        if self.current == Some(slot_index) {
            let _ = self.account_running(now_ns);
        }
        let Some((old_policy, old_queue, old_start, old_finish, old_job, old_state)) =
            self.task(slot_index).map(|slot| {
                (
                    slot.task.sched_policy,
                    slot.queue,
                    slot.request_start,
                    slot.request_finish,
                    slot.task.job_id,
                    slot.task.lifecycle.state(),
                )
            })
        else {
            return;
        };
        if old_policy == policy {
            return;
        }
        let old_weight = Self::weight(old_policy);
        let new_weight = Self::weight(policy);
        let old_fair = Self::policy_is_fair(old_policy);
        let new_fair = Self::policy_is_fair(policy);
        let new_cbs = if new_fair {
            None
        } else {
            let Some(cbs) = Self::create_cbs(policy, now_ns) else {
                return;
            };
            Some(cbs)
        };
        if old_queue != QueueKind::None {
            self.remove_task_queue(slot_index);
        }
        let runnable = matches!(old_state, TaskState::Ready | TaskState::Running);
        if runnable {
            let Some(job_index) = self.job_index(old_job) else {
                scheduler_fail_stop();
            };
            if self.job_queues[job_index]
                .accounting
                .thread_blocked(0, old_weight)
                .is_err()
                || self.job_queues[job_index]
                    .accounting
                    .thread_ready(0, new_weight)
                    .is_err()
            {
                scheduler_fail_stop();
            }
        }
        if old_fair && runnable {
            self.update_fair_population(old_job, -1);
        }
        let new_request = if new_fair {
            let Some(job_index) = self.job_index(old_job) else {
                scheduler_fail_stop();
            };
            let virtual_time = self.job_queues[job_index].virtual_time;
            let converted = convert_lag(
                signed_delta(virtual_time, old_start),
                old_weight,
                new_weight,
            );
            let start = signed_subtract(virtual_time, converted);
            let (finish, remaining) = Self::make_request(start, FAIR_REQUEST_NS, new_weight);
            Some((start, finish, remaining))
        } else {
            None
        };
        if let Some(slot) = self.task_mut(slot_index) {
            slot.task.sched_policy = policy;
            slot.cbs = new_cbs;
            slot.queue = QueueKind::None;
            if let Some((start, finish, remaining)) = new_request {
                slot.request_start = start;
                slot.request_finish = finish;
                slot.request_remaining_ns = remaining;
            }
        }
        if new_fair && runnable {
            self.update_fair_population(old_job, 1);
        }
        if runnable && self.current != Some(slot_index) {
            if new_fair {
                let Some(job_index) = self.job_index(old_job) else {
                    scheduler_fail_stop();
                };
                if self.job_queues[job_index].threads.is_full() {
                    scheduler_fail_stop();
                }
                self.insert_fair_tree(slot_index);
            } else {
                self.enqueue_refill_or_deadline(slot_index);
            }
        }
        let _ = old_finish;
        record_task(
            slot_index,
            self.task(slot_index).map(|slot| &*slot.task),
            self.cpu,
            if old_state == TaskState::Running {
                0
            } else {
                1
            },
        );
        publish_cpu_stats(self);
    }

    fn reap_task(&mut self, id: u64, slot_index: usize) -> Option<Box<Task>> {
        self.assert_owner();
        if !self.task_matches(id) || self.current == Some(slot_index) {
            return None;
        }
        let slot = self.task(slot_index)?;
        if !slot.task.finished.load(Ordering::Acquire)
            || slot.task.lifecycle.state() != TaskState::Dead
            || slot.queue != QueueKind::None
        {
            return None;
        }
        let task_id = V2TaskId::from_raw(id)?;
        let discarded = match TASK_DIRECTORY.retire(task_id) {
            Ok(flags) => flags,
            Err(_) => return None,
        };
        if discarded != 0 {
            OBS_REAP_DISCARDED_OP_FLAGS.fetch_add(discarded.count_ones() as u64, Ordering::Relaxed);
            OBS_REAP_TASKS_WITH_DISCARDED_OPS.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(slot) = self.task_mut(slot_index) {
            if slot.task.lifecycle.reap().is_err() {
                scheduler_fail_stop();
            }
        }
        let removed = self.tasks.get_mut(slot_index)?.take()?;
        let _ = TASK_SLOTS.free(task_id.slot());
        self.task_count = self.task_count.saturating_sub(1);
        LIVE_TASK_COUNT.fetch_sub(1, Ordering::AcqRel);
        TASK_RECORDS[slot_index].clear();
        publish_cpu_stats(self);
        Some(removed.task)
    }

    fn current_id(&self) -> u64 {
        self.current
            .and_then(|slot| self.task(slot).map(|task| task.task.id))
            .map_or(0, |id| id)
    }
}

struct SwitchDecision {
    target: SwitchTarget,
    environment: TaskEnvironment,
}
struct ScheduleResult {
    decision: Option<SwitchDecision>,
    charge_process: Option<Arc<Process>>,
}

static PER_CPU_SCHEDULERS: [RankedIrqSafeTicketLock<Scheduler>; MAX_CPUS] =
    [const { RankedIrqSafeTicketLock::new(Scheduler::new(), LockRank::SCHEDULER) }; MAX_CPUS];

/// Global task record snapshot cells. All fields are atomic so telemetry never
/// reads or locks a remote CPU's runqueue.
struct TaskRecordCell {
    sequence: AtomicU64,
    id: AtomicU64,
    name0: AtomicU64,
    name1: AtomicU64,
    cpu: AtomicU32,
    weight: AtomicU32,
    kind: AtomicU32,
    state: AtomicU32,
    policy: AtomicU32,
    process_koid: AtomicU64,
}
impl TaskRecordCell {
    const fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            id: AtomicU64::new(0),
            name0: AtomicU64::new(0),
            name1: AtomicU64::new(0),
            cpu: AtomicU32::new(0),
            weight: AtomicU32::new(0),
            kind: AtomicU32::new(0),
            state: AtomicU32::new(1),
            policy: AtomicU32::new(0),
            process_koid: AtomicU64::new(0),
        }
    }

    fn store(&self, record: huesos_abi::TaskRecord) {
        self.sequence.fetch_add(1, Ordering::AcqRel);
        self.id.store(record.task_id, Ordering::Relaxed);
        let mut name0 = [0u8; 8];
        let mut name1 = [0u8; 8];
        name0.copy_from_slice(&record.name[..8]);
        name1.copy_from_slice(&record.name[8..]);
        self.name0
            .store(u64::from_ne_bytes(name0), Ordering::Relaxed);
        self.name1
            .store(u64::from_ne_bytes(name1), Ordering::Relaxed);
        self.cpu.store(u32::from(record.cpu), Ordering::Relaxed);
        self.weight
            .store(u32::from(record.weight), Ordering::Relaxed);
        self.kind.store(u32::from(record.kind), Ordering::Relaxed);
        self.state.store(u32::from(record.state), Ordering::Relaxed);
        self.policy
            .store(u32::from(record.policy), Ordering::Relaxed);
        self.process_koid
            .store(record.process_koid(), Ordering::Relaxed);
        self.sequence.fetch_add(1, Ordering::Release);
    }

    fn clear(&self) {
        self.sequence.fetch_add(1, Ordering::AcqRel);
        self.id.store(0, Ordering::Relaxed);
        self.process_koid.store(0, Ordering::Relaxed);
        self.sequence.fetch_add(1, Ordering::Release);
    }

    fn load(&self) -> Option<huesos_abi::TaskRecord> {
        for _ in 0..8 {
            let before = self.sequence.load(Ordering::Acquire);
            if before & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            let id = self.id.load(Ordering::Relaxed);
            if id == 0 {
                return None;
            }
            let name0 = self.name0.load(Ordering::Relaxed).to_ne_bytes();
            let name1 = self.name1.load(Ordering::Relaxed).to_ne_bytes();
            let mut name = [0u8; 16];
            name[..8].copy_from_slice(&name0);
            name[8..].copy_from_slice(&name1);
            let record = huesos_abi::TaskRecord {
                task_id: id,
                name,
                cpu: self.cpu.load(Ordering::Relaxed) as u16,
                weight: self.weight.load(Ordering::Relaxed) as u16,
                kind: self.kind.load(Ordering::Relaxed) as u8,
                state: self.state.load(Ordering::Relaxed) as u8,
                policy: self.policy.load(Ordering::Relaxed) as u8,
                flags: 0,
                reserved: self.process_koid.load(Ordering::Relaxed),
            };
            let after = self.sequence.load(Ordering::Acquire);
            if before == after {
                return Some(record);
            }
        }
        None
    }
}
static TASK_RECORDS: [TaskRecordCell; huesos_sched::MAX_TASKS] =
    [const { TaskRecordCell::new() }; huesos_sched::MAX_TASKS];
static LIVE_TASK_COUNT: AtomicUsize = AtomicUsize::new(0);
static CURRENT_TASK_IDS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static CURRENT_PROCESS_KOIDS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static CPU_RUNNABLE: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(0) }; MAX_CPUS];
static CPU_TASKS: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(0) }; MAX_CPUS];
static CPU_TICKS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static CPU_ADMITTED_PPM: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

/// Per-CPU CBS and threaded-IRQ admission ceilings.
static CBS_ADMISSION: [RankedIrqSafeTicketLock<AdmissionControl>; MAX_CPUS] = [const {
    RankedIrqSafeTicketLock::new(AdmissionControl::production_default(), LockRank::SCHEDULER)
}; MAX_CPUS];

static OBS_CTX_SWITCHES: AtomicU64 = AtomicU64::new(0);
static OBS_REMOTE_WAKES: AtomicU64 = AtomicU64::new(0);
static OBS_RESCHED_IPIS: AtomicU64 = AtomicU64::new(0);
static OBS_INBOX_DRAINS: AtomicU64 = AtomicU64::new(0);
static OBS_IRQ_STORM_MASKS: AtomicU64 = AtomicU64::new(0);
static OBS_REAP_DISCARDED_OP_FLAGS: AtomicU64 = AtomicU64::new(0);
static OBS_REAP_TASKS_WITH_DISCARDED_OPS: AtomicU64 = AtomicU64::new(0);

fn record_task(slot: usize, task: Option<&Task>, cpu: usize, state: u8) {
    let Some(task) = task else {
        return;
    };
    if slot >= huesos_sched::MAX_TASKS {
        return;
    }
    let (kind, process_koid) = match &task.kind {
        TaskKind::Kernel => (0u8, 0u64),
        TaskKind::User { process, .. } => (1u8, process.koid().0),
        TaskKind::Reaped => (0u8, 0u64),
    };
    let (policy, weight) = match task.sched_policy {
        SchedPolicy::Fair { weight } => (0u8, weight.min(u64::from(u16::MAX)) as u16),
        SchedPolicy::Deadline { .. } => (1u8, 0u16),
    };
    let mut name = [0u8; 16];
    name.copy_from_slice(&task.name[..16]);
    TASK_RECORDS[slot].store(huesos_abi::TaskRecord {
        task_id: task.id,
        name,
        cpu: cpu as u16,
        weight,
        kind,
        state,
        policy,
        flags: 0,
        reserved: process_koid,
    });
}

fn publish_cpu_stats(scheduler: &Scheduler) {
    let cpu = scheduler.cpu;
    if cpu >= MAX_CPUS {
        return;
    }
    CPU_RUNNABLE[cpu].store(scheduler.ready_count, Ordering::Release);
    CPU_TASKS[cpu].store(scheduler.task_count, Ordering::Release);
    CPU_TICKS[cpu].store(scheduler.ticks, Ordering::Release);
    CURRENT_TASK_IDS[cpu].store(scheduler.current_id(), Ordering::Release);
}

fn signed_delta(now: u128, start: u128) -> i128 {
    if now >= start {
        (now - start).min(i128::MAX as u128) as i128
    } else {
        -((start - now).min(i128::MAX as u128) as i128)
    }
}

fn signed_subtract(base: u128, delta: i128) -> u128 {
    if delta >= 0 {
        base.saturating_sub(delta as u128)
    } else {
        base.saturating_add(delta.unsigned_abs())
    }
}

fn bound_lag(lag: i128, maximum: u128) -> i128 {
    let max = maximum.min(i128::MAX as u128) as i128;
    lag.clamp(-max, max)
}

fn convert_lag(lag: i128, old_weight: u64, new_weight: u64) -> i128 {
    let old = old_weight.max(1);
    let new = new_weight.max(1);
    let numerator = lag.saturating_mul(i128::from(old));
    numerator / i128::from(new)
}

fn task_location(id: u64) -> Option<TaskLocation> {
    TASK_DIRECTORY.locate(V2TaskId::from_raw(id)?).ok()
}

fn cpu_id() -> usize {
    // SAFETY: scheduler entry points run only after GS_BASE is initialized.
    (unsafe { huesos_arch::cpu_local::current_cpu_index() }).min(MAX_CPUS - 1)
}

fn lapic_id_for_cpu_index(cpu: usize) -> Option<u8> {
    huesos_arch::cpu_local::lapic_id_for_index(cpu).and_then(|id| u8::try_from(id).ok())
}

/// Register the current CPU's stable Scheduler address in CpuLocal.
///
/// # Safety
/// Must be called once per CPU after `cpu_local::init_gs_base`.
unsafe fn register_scheduler_ptr(scheduler: *mut Scheduler) {
    let local = huesos_arch::cpu_local::cpu_local_ptr();
    unsafe { (*local).scheduler = scheduler as *mut () };
}

#[track_caller]
fn scheduler_fail_stop() -> ! {
    log::error!("scheduler invariant failed; CPU stopped");
    huesos_arch::interrupts::disable();
    huesos_arch::serial::emergency_write("[sched] fatal scheduler invariant violation\n");
    loop {
        huesos_arch::hlt();
    }
}

fn queue_ipi(cpu: usize) {
    if let Some(apic_id) = lapic_id_for_cpu_index(cpu) {
        OBS_RESCHED_IPIS.fetch_add(1, Ordering::Relaxed);
        huesos_arch::lapic::ipi_reschedule(apic_id);
    }
}

fn publish_remote_operation(id: V2TaskId, operations: u64, owner: usize) -> bool {
    if owner >= MAX_CPUS || TASK_DIRECTORY.publish_operations(id, operations).is_err() {
        return false;
    }
    let Some(result) = CPU_INBOX[owner].publish(id.slot()) else {
        return false;
    };
    if result.send_ipi {
        queue_ipi(owner);
    }
    true
}

fn place_pending_task(id: V2TaskId, cpu: usize, task: Box<Task>) -> Result<(), Box<Task>> {
    let mut pending = PENDING_TASKS.lock();
    let slot = id.slot();
    if pending.len() <= slot {
        let additional = slot + 1 - pending.len();
        if pending.try_reserve(additional).is_err() {
            return Err(task);
        }
        pending.resize_with(slot + 1, || None);
    }
    if pending[slot].is_some() {
        return Err(task);
    }
    if cpu < MAX_CPUS {
        CPU_PENDING_SPAWNS[cpu].fetch_add(1, Ordering::AcqRel);
    }
    pending[slot] = Some(PendingTask {
        id: id.raw(),
        cpu,
        task,
    });
    Ok(())
}

fn take_pending_task(id: V2TaskId) -> Option<Box<Task>> {
    let mut pending = PENDING_TASKS.lock();
    let entry = pending.get_mut(id.slot())?.take()?;
    if entry.id == id.raw() {
        if entry.cpu < MAX_CPUS {
            let _ = CPU_PENDING_SPAWNS[entry.cpu].try_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |n| Some(n.saturating_sub(1)),
            );
        }
        Some(entry.task)
    } else {
        pending[id.slot()] = Some(entry);
        None
    }
}

fn take_policy_request(id: u64) -> Option<SchedPolicy> {
    let mut requests = POLICY_REQUESTS.lock();
    let position = requests.iter().position(|(task_id, _)| *task_id == id)?;
    Some(requests.swap_remove(position).1)
}

fn set_policy_request(id: u64, policy: SchedPolicy) {
    let mut requests = POLICY_REQUESTS.lock();
    if let Some((_, pending)) = requests.iter_mut().find(|(task_id, _)| *task_id == id) {
        *pending = policy;
    } else {
        requests.push((id, policy));
    }
}

fn clear_task_identity(id: u64) {
    if let Some(task_id) = V2TaskId::from_raw(id) {
        let _ = TASK_DIRECTORY.retire(task_id);
        let _ = TASK_SLOTS.free(task_id.slot());
        TASK_RECORDS[task_id.slot()].clear();
        LIVE_TASK_COUNT.fetch_sub(1, Ordering::AcqRel);
    }
}

// Keep the Box until all scheduler/Task cleanup is complete; dropping a Task
// here also releases its separately allocated kernel stack.
#[allow(clippy::boxed_local)]
fn finish_failed_spawn(task: Box<Task>) {
    crate::process::cancel_user_entry(task.id);
    let mut process_to_teardown = None;
    match &task.kind {
        TaskKind::User { process, thread } => {
            if let Some(thread) = thread {
                let _ = thread.set_exit_code(huesos_abi::ErrorCode::NoMemory as i64);
            }
            let previous = process.decrement_active_threads();
            if previous <= 1 && process.set_exit_code(huesos_abi::ErrorCode::NoMemory as i64) {
                record_process_exit(process, huesos_abi::ErrorCode::NoMemory as i64);
                process_to_teardown = Some(Arc::clone(process));
            }
        }
        TaskKind::Kernel | TaskKind::Reaped => {}
    }
    clear_task_identity(task.id);
    if let Some(process) = process_to_teardown {
        PROCESS_TEARDOWN.lock().push(process);
        REAP_PENDING.store(true, Ordering::Release);
    }
}

fn process_inbox_task(cpu: usize, slot: usize) {
    if cpu != cpu_id() || slot >= huesos_sched::MAX_TASKS {
        return;
    }
    let Some(id) = TASK_DIRECTORY.published_id(slot) else {
        return;
    };
    let raw_id = id.raw();
    let Some(location) = task_location(raw_id) else {
        return;
    };
    if location.owner.as_usize() != cpu || location.local_index as usize != slot {
        return;
    }
    let operations = TASK_DIRECTORY.take_operations(id).map_or(0, |flags| flags);
    if operations == 0 {
        return;
    }
    let pending_task = if operations & task_operations::SPAWN != 0 {
        take_pending_task(id)
    } else {
        None
    };
    let policy = if operations & task_operations::POLICY != 0 {
        take_policy_request(raw_id)
    } else {
        None
    };
    let exit_code = KILL_EXIT_CODES[slot].load(Ordering::Acquire);
    let now_ns = monotonic_ns();
    let mut failed_spawn = None;
    let mut reaped_task = None;
    {
        let mut scheduler = PER_CPU_SCHEDULERS[cpu].lock();
        scheduler.assert_owner();
        if let Some(task) = pending_task {
            if scheduler.task_matches(raw_id) {
                failed_spawn = Some(task);
            } else if let Err(task) = scheduler.insert_task(cpu, task, now_ns) {
                failed_spawn = Some(task);
            }
        }
        if scheduler.task_matches(raw_id) {
            let slot_index = location.local_index as usize;
            if operations & task_operations::WAKE != 0 {
                scheduler.apply_wake(raw_id, slot_index, now_ns);
            }
            if let Some(policy) = policy {
                scheduler.apply_policy(raw_id, slot_index, policy, now_ns);
            }
            if operations & task_operations::KILL != 0 {
                scheduler.mark_dead(raw_id, slot_index, exit_code, now_ns);
            }
            if operations & task_operations::REAP != 0 {
                reaped_task = scheduler.reap_task(raw_id, slot_index);
            }
        }
        publish_cpu_stats(&scheduler);
    }
    if let Some(task) = failed_spawn {
        clear_task_identity(raw_id);
        finish_failed_spawn(task);
    }
    if let Some(task) = reaped_task {
        deferred_task_drop(task);
    }
}

fn deferred_task_drop(task: Box<Task>) {
    DEFERRED_TASK_DROPS.lock().push(task);
}

fn run_current_cpu_scheduler_interrupt(hardware_tick: bool) {
    let was_enabled = x86_64::instructions::interrupts::are_enabled();
    huesos_arch::interrupts::disable();
    let allow_preempt = huesos_arch::preemption::can_preempt();
    if !allow_preempt && !hardware_tick {
        huesos_arch::preemption::request_reschedule();
        if was_enabled {
            huesos_arch::interrupts::enable();
        }
        return;
    }
    if allow_preempt {
        let _ = huesos_arch::preemption::take_reschedule_request();
    } else {
        huesos_arch::preemption::request_reschedule();
    }
    let cpu = cpu_id();
    let drained = CPU_INBOX[cpu].drain(|slot| process_inbox_task(cpu, slot));
    OBS_INBOX_DRAINS.fetch_add(drained as u64, Ordering::Relaxed);
    if hardware_tick && cpu == 0 {
        MONOTONIC_TICKS.fetch_add(1, Ordering::SeqCst);
    }
    let now_ns = monotonic_ns();
    let result = {
        let mut scheduler = PER_CPU_SCHEDULERS[cpu].lock();
        if allow_preempt {
            scheduler.schedule(now_ns, hardware_tick)
        } else {
            ScheduleResult {
                decision: None,
                charge_process: scheduler.tick_without_preempt(now_ns),
            }
        }
    };
    if hardware_tick {
        if let Some(process) = result.charge_process.as_ref() {
            let _ = process.charge_cpu_tick();
        }
        if cpu == 0 {
            huesos_object::wait::notify_tick(MONOTONIC_TICKS.load(Ordering::SeqCst));
        }
        if TSC_DEADLINE_ACTIVE.load(Ordering::Relaxed) {
            if let Some(clock) = TSC_CLOCK.get() {
                let deadline = huesos_arch::rdtsc().saturating_add(clock.ns_to_cycles(TICK_NS));
                // SAFETY: LAPIC initialization completed before scheduler init.
                unsafe { huesos_arch::lapic::timer_arm_tsc_deadline(deadline, 0x20) };
            }
        }
    }
    if let Some(decision) = result.decision {
        decision.environment.install();
        perform_context_switch(decision.target);
    }
    drop(result.charge_process);
    if was_enabled {
        huesos_arch::interrupts::enable();
    }
}

/// Initialize the owner CPU scheduler and install its timer callbacks.
pub fn init() {
    TSC_CLOCK.call_once(|| {
        let hz = huesos_arch::lapic::calibrate_tsc_hz();
        match TscClock::from_frequency(hz) {
            Ok(clock) => clock,
            Err(_) => match TscClock::from_frequency(1_000_000_000) {
                Ok(clock) => clock,
                Err(_) => scheduler_fail_stop(),
            },
        }
    });
    let was_enabled = x86_64::instructions::interrupts::are_enabled();
    huesos_arch::interrupts::disable();
    let cpu = cpu_id();
    let idle_guards = {
        let mut scheduler = PER_CPU_SCHEDULERS[cpu].lock();
        scheduler.cpu = cpu;
        scheduler.last_account_ns = monotonic_ns();
        if scheduler.idle_task.is_none() {
            scheduler.idle_task = Some(Box::new(Task::new_idle(
                0,
                *b"idle\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            )));
        }
        // SAFETY: the scheduler array has static storage and this CPU is its
        // only writer; no context switch can occur while interrupts are off.
        unsafe { register_scheduler_ptr(&mut *scheduler) };
        let Some(idle_task) = scheduler.idle_task.as_mut() else {
            scheduler_fail_stop();
        };
        &raw mut idle_task.execution_guards
    };
    // SAFETY: task zero is a stable Box retained by this CPU's scheduler.
    unsafe { huesos_arch::cpu_local::install_execution_guards(idle_guards) };
    huesos_object::clear_current_process();
    if was_enabled {
        huesos_arch::interrupts::enable();
    }

    huesos_arch::timer_callback::set_timer_callback(&|| {
        run_current_cpu_scheduler_interrupt(true);
    });
    huesos_arch::timer_callback::set_reschedule_callback(&|| {
        run_current_cpu_scheduler_interrupt(false);
    });
    huesos_arch::preemption::set_reschedule_hook(deferred_reschedule_hook);

    let force_deadline = core::option_env!("HUESOS_FORCE_TSC_DEADLINE").is_some();
    if huesos_arch::lapic::tsc_deadline_supported()
        && (huesos_arch::lapic::tsc_invariant() || force_deadline)
        && TSC_CLOCK.get().is_some()
    {
        TSC_DEADLINE_ACTIVE.store(true, Ordering::Relaxed);
        huesos_arch::lapic::timer_stop();
        if let Some(clock) = TSC_CLOCK.get() {
            let deadline = huesos_arch::rdtsc().saturating_add(clock.ns_to_cycles(TICK_NS));
            // SAFETY: LAPIC initialization completed before scheduler init.
            unsafe { huesos_arch::lapic::timer_arm_tsc_deadline(deadline, 0x20) };
        }
    }
    mark_cpu_online();
}

fn deferred_reschedule_hook() {
    run_current_cpu_scheduler_interrupt(false);
}

/// Yield the current task cooperatively.
pub fn yield_now() {
    run_current_cpu_scheduler_interrupt(false);
}

/// Service any latched reschedule request on the current CPU when preemption
/// is permitted (used on syscall exit so local wakes/spawns preempt promptly).
pub fn reschedule_if_pending() {
    if huesos_arch::preemption::can_preempt() && huesos_arch::preemption::take_reschedule_request()
    {
        run_current_cpu_scheduler_interrupt(false);
    }
}

/// Park the current task after the wait-queue enqueue handshake.
pub fn park_current() {
    let was_enabled = x86_64::instructions::interrupts::are_enabled();
    huesos_arch::interrupts::disable();
    let _ = huesos_arch::preemption::take_reschedule_request();
    let cpu = cpu_id();
    let drained = CPU_INBOX[cpu].drain(|slot| process_inbox_task(cpu, slot));
    OBS_INBOX_DRAINS.fetch_add(drained as u64, Ordering::Relaxed);
    let now_ns = monotonic_ns();
    {
        let mut scheduler = PER_CPU_SCHEDULERS[cpu].lock();
        scheduler.block_current(now_ns);
    }
    let result = {
        let mut scheduler = PER_CPU_SCHEDULERS[cpu].lock();
        scheduler.schedule(now_ns, false)
    };
    if let Some(decision) = result.decision {
        decision.environment.install();
        perform_context_switch(decision.target);
    }
    if was_enabled {
        huesos_arch::interrupts::enable();
    }
}

/// Wake a parked task. Remote wakes are asynchronous and coalesced by inbox.
pub fn wake_task(task_id: u64) {
    let Some(location) = task_location(task_id) else {
        return;
    };
    let cpu = location.owner.as_usize();
    let Some(id) = V2TaskId::from_raw(task_id) else {
        return;
    };
    if cpu >= MAX_CPUS {
        return;
    }
    if cpu == cpu_id() {
        let now_ns = monotonic_ns();
        let mut scheduler = PER_CPU_SCHEDULERS[cpu].lock();
        if scheduler.task_matches(task_id) {
            scheduler.apply_wake(task_id, location.local_index as usize, now_ns);
        }
        return;
    }
    OBS_REMOTE_WAKES.fetch_add(1, Ordering::Relaxed);
    let _ = publish_remote_operation(id, task_operations::WAKE, cpu);
}

/// Get the current task ID (idle is the distinguished ID zero).
pub fn current_task_id() -> Option<u64> {
    let scheduler = PER_CPU_SCHEDULERS[cpu_id()].lock();
    Some(scheduler.current_id())
}

/// Update the calling user thread's FS base after lower-half validation.
pub fn set_current_fs_base(fs_base: u64) -> Result<(), huesos_abi::ErrorCode> {
    if fs_base >= huesos_abi::USER_ASPACE_END {
        return Err(huesos_abi::ErrorCode::InvalidArgs);
    }
    let mut scheduler = PER_CPU_SCHEDULERS[cpu_id()].lock();
    scheduler.assert_owner();
    let Some(slot_index) = scheduler.current else {
        return Err(huesos_abi::ErrorCode::NotFound);
    };
    let Some(task) = scheduler.task_mut(slot_index) else {
        return Err(huesos_abi::ErrorCode::NotFound);
    };
    task.task.context.fs_base = fs_base;
    huesos_arch::context_switch::write_fs_base(fs_base);
    Ok(())
}

/// Mark a user task's initial entry record consumed after its trampoline runs.
pub(crate) fn mark_user_entry_consumed(task_id: u64) {
    let Some(location) = task_location(task_id) else {
        return;
    };
    if location.owner.as_usize() != cpu_id() {
        return;
    }
    let mut scheduler = PER_CPU_SCHEDULERS[cpu_id()].lock();
    if scheduler.task_matches(task_id) {
        if let Some(task) = scheduler.task_mut(location.local_index as usize) {
            task.task.startup_pending.store(false, Ordering::Release);
        }
    }
}

/// Monotonic BSP scheduler tick count used by waits and timeouts.
pub fn global_ticks() -> u64 {
    MONOTONIC_TICKS.load(Ordering::SeqCst)
}

/// Monotonic nanoseconds derived from the calibrated invariant TSC.
pub fn monotonic_ns() -> u64 {
    TSC_CLOCK
        .get()
        .map_or(0, |clock| clock.cycles_to_ns(huesos_arch::rdtsc()))
}

/// Whether the hardware TSC is invariant.
pub fn tsc_clock_invariant() -> bool {
    huesos_arch::lapic::tsc_invariant()
}

/// CBS admission failure reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CbsError {
    /// CPU index is invalid or offline.
    CpuInvalid,
    /// Reservation parameters are invalid.
    InvalidReservation,
    /// The 80% ceiling would be exceeded.
    Overcommitted,
    /// The reservation was not admitted.
    NotAdmitted,
}

/// Reserve CBS/IRQ bandwidth on one CPU.
pub fn cbs_try_admit(cpu: usize, capacity_ns: u64, period_ns: u64) -> Result<(), CbsError> {
    if cpu >= MAX_CPUS || !is_cpu_online(cpu) {
        return Err(CbsError::CpuInvalid);
    }
    let reservation = CbsReservation::new(capacity_ns, period_ns, period_ns)
        .map_err(|_| CbsError::InvalidReservation)?;
    let ppm = CBS_ADMISSION[cpu]
        .lock()
        .reserve(reservation)
        .map_err(|_| CbsError::Overcommitted)?;
    CPU_ADMITTED_PPM[cpu].store(CBS_ADMISSION[cpu].lock().admitted_ppm(), Ordering::Release);
    let _ = ppm;
    Ok(())
}

/// Release a previously admitted CBS/IRQ reservation.
pub fn cbs_release(cpu: usize, capacity_ns: u64, period_ns: u64) -> Result<(), CbsError> {
    if cpu >= MAX_CPUS || !is_cpu_online(cpu) {
        return Err(CbsError::CpuInvalid);
    }
    let reservation = CbsReservation::new(capacity_ns, period_ns, period_ns)
        .map_err(|_| CbsError::InvalidReservation)?;
    let ppm = reservation
        .utilization_ppm()
        .map_err(|_| CbsError::InvalidReservation)?;
    let mut admission = CBS_ADMISSION[cpu].lock();
    admission
        .release_ppm(ppm)
        .map_err(|_| CbsError::NotAdmitted)?;
    CPU_ADMITTED_PPM[cpu].store(admission.admitted_ppm(), Ordering::Release);
    Ok(())
}

/// Admitted utilization on one CPU in parts per million.
pub fn cbs_admitted_ppm(cpu: usize) -> u32 {
    CPU_ADMITTED_PPM
        .get(cpu)
        .map_or(0, |ppm| ppm.load(Ordering::Acquire))
}

/// Aggregate scheduler counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SchedStats {
    pub context_switches: u64,
    pub remote_wakes: u64,
    pub resched_ipis: u64,
    pub inbox_drains: u64,
    pub irq_storm_masks: u64,
    pub reap_discarded_op_flags: u64,
    pub reap_tasks_with_discarded_ops: u64,
}

/// Read aggregate scheduler counters.
pub fn sched_stats() -> SchedStats {
    SchedStats {
        context_switches: OBS_CTX_SWITCHES.load(Ordering::Relaxed),
        remote_wakes: OBS_REMOTE_WAKES.load(Ordering::Relaxed),
        resched_ipis: OBS_RESCHED_IPIS.load(Ordering::Relaxed),
        inbox_drains: OBS_INBOX_DRAINS.load(Ordering::Relaxed),
        irq_storm_masks: OBS_IRQ_STORM_MASKS.load(Ordering::Relaxed),
        reap_discarded_op_flags: OBS_REAP_DISCARDED_OP_FLAGS.load(Ordering::Relaxed),
        reap_tasks_with_discarded_ops: OBS_REAP_TASKS_WITH_DISCARDED_OPS.load(Ordering::Relaxed),
    }
}

/// Fill one aggregate scheduler ABI record.
pub fn sched_summary(out: &mut huesos_abi::SchedSummary) {
    let stats = sched_stats();
    let online = online_cpu_mask_words();
    let admitted = (0..MAX_CPUS)
        .filter(|cpu| online[*cpu / 64] & (1u64 << (*cpu % 64)) != 0)
        .map(cbs_admitted_ppm)
        .map(u64::from)
        .sum();
    *out = huesos_abi::SchedSummary {
        cpu_count: online.iter().map(|word| word.count_ones()).sum(),
        record_size: core::mem::size_of::<huesos_abi::SchedCpuRecord>() as u32,
        context_switches: stats.context_switches,
        remote_wakes: stats.remote_wakes,
        resched_ipis: stats.resched_ipis,
        inbox_drains: stats.inbox_drains,
        irq_storm_masks: stats.irq_storm_masks,
        admitted_ppm: admitted,
    };
}

/// Fill one CPU scheduler ABI record from owner-published atomics only.
pub fn sched_cpu_record(cpu: usize, out: &mut huesos_abi::SchedCpuRecord) {
    if cpu >= MAX_CPUS || !is_cpu_online(cpu) {
        *out = huesos_abi::SchedCpuRecord {
            cpu: cpu as u32,
            ..Default::default()
        };
        return;
    }
    *out = huesos_abi::SchedCpuRecord {
        cpu: cpu as u32,
        online: 1,
        runnable: CPU_RUNNABLE[cpu]
            .load(Ordering::Acquire)
            .min(u32::MAX as usize) as u32,
        tasks: CPU_TASKS[cpu]
            .load(Ordering::Acquire)
            .min(u32::MAX as usize) as u32,
        current_task: CURRENT_TASK_IDS[cpu].load(Ordering::Acquire),
        ticks: CPU_TICKS[cpu].load(Ordering::Acquire),
        admitted_ppm: cbs_admitted_ppm(cpu),
        reserved: 0,
    };
}

/// Read one global, lock-free task-table page. `reserved` carries the real
/// owning Process KOID for user tasks.
pub fn task_records_page(start: usize, out: &mut [huesos_abi::TaskRecord]) -> (usize, usize) {
    let mut seen = 0usize;
    let mut written = 0usize;
    for cell in TASK_RECORDS.iter() {
        let Some(record) = cell.load() else {
            continue;
        };
        if seen >= start && written < out.len() {
            out[written] = record;
            written += 1;
        }
        seen += 1;
    }
    (written, LIVE_TASK_COUNT.load(Ordering::Acquire).max(seen))
}

/// Number of published live Tasks.
pub fn task_count() -> usize {
    LIVE_TASK_COUNT.load(Ordering::Acquire)
}

/// Record that an IRQ source was masked due to a storm/budget violation.
pub fn irq_storm_masked() {
    OBS_IRQ_STORM_MASKS.fetch_add(1, Ordering::Relaxed);
}

/// Change one Task policy. Remote changes carry their payload with the async
/// POLICY operation and are applied by the owner.
pub fn set_sched_policy(task_id: u64, policy: SchedPolicy) {
    let Some(location) = task_location(task_id) else {
        return;
    };
    let cpu = location.owner.as_usize();
    let Some(id) = V2TaskId::from_raw(task_id) else {
        return;
    };
    if cpu >= MAX_CPUS {
        return;
    }
    if cpu == cpu_id() {
        let now_ns = monotonic_ns();
        let mut scheduler = PER_CPU_SCHEDULERS[cpu].lock();
        scheduler.apply_policy(task_id, location.local_index as usize, policy, now_ns);
    } else {
        set_policy_request(task_id, policy);
        let _ = publish_remote_operation(id, task_operations::POLICY, cpu);
    }
}

/// Spawn a kernel thread on the calling CPU.
pub fn spawn_kernel_thread(name: &[u8; 32], entry: extern "C" fn() -> !) -> Option<u64> {
    let cpu = cpu_id();
    let (slot, generation) = TASK_SLOTS.allocate()?;
    let id = V2TaskId::new(slot, generation)?;
    let task = Box::new(Task::new_kernel(id.raw(), *name, entry));
    let now_ns = monotonic_ns();
    let was_enabled = x86_64::instructions::interrupts::are_enabled();
    huesos_arch::interrupts::disable();
    let installed = {
        let mut scheduler = PER_CPU_SCHEDULERS[cpu].lock();
        if TASK_DIRECTORY
            .publish(id, CpuIndex::new(cpu)?, slot)
            .is_err()
        {
            false
        } else if scheduler.insert_task(cpu, task, now_ns).is_err() {
            let _ = TASK_DIRECTORY.retire(id);
            false
        } else {
            record_task(slot, scheduler.task(slot).map(|task| &*task.task), cpu, 1);
            LIVE_TASK_COUNT.fetch_add(1, Ordering::AcqRel);
            true
        }
    };
    if !installed {
        let _ = TASK_SLOTS.free(slot);
    }
    if was_enabled {
        huesos_arch::interrupts::enable();
    }
    if installed && cpu != cpu_id() {
        queue_ipi(cpu);
    }
    installed.then_some(id.raw())
}

/// Select the least-loaded online CPU permitted by `allowed_mask` (`None`
/// permits all online CPUs), breaking ties round-robin across online cores.
pub fn select_least_loaded_cpu(
    allowed_mask: Option<&[u64; huesos_abi::CPU_MASK256_WORDS]>,
) -> usize {
    let online = online_cpu_mask_words();
    let start = NEXT_SPAWN_CPU.fetch_add(1, Ordering::Relaxed) % MAX_CPUS;
    let mut best_cpu = None;
    let mut best_score = (usize::MAX, usize::MAX);

    for offset in 0..MAX_CPUS {
        let cpu = (start + offset) % MAX_CPUS;
        let word = cpu / 64;
        let bit = 1u64 << (cpu % 64);
        if online[word] & bit == 0 {
            continue;
        }
        if let Some(mask) = allowed_mask {
            if mask[word] & bit == 0 {
                continue;
            }
        }
        let running = usize::from(CURRENT_TASK_IDS[cpu].load(Ordering::Acquire) != 0);
        let pending = CPU_PENDING_SPAWNS[cpu].load(Ordering::Acquire);
        let active = running
            .saturating_add(CPU_RUNNABLE[cpu].load(Ordering::Acquire))
            .saturating_add(pending);
        let total = CPU_TASKS[cpu]
            .load(Ordering::Acquire)
            .saturating_add(pending);
        let score = (active, total);
        if best_cpu.is_none() || score < best_score {
            best_cpu = Some(cpu);
            best_score = score;
            if score == (0, 0) {
                break;
            }
        }
    }

    best_cpu.unwrap_or_else(cpu_id)
}

/// Spawn a user task on the least-loaded online CPU.
pub fn spawn_user_thread(
    name: &[u8; 32],
    process: Arc<Process>,
    entry_point: u64,
    user_rsp: u64,
    cr3: u64,
) -> u64 {
    let target_cpu = select_least_loaded_cpu(None);
    process.record_default_cpu(target_cpu);
    spawn_user_thread_on_cpu(name, process, entry_point, user_rsp, cr3, target_cpu)
        .unwrap_or(u64::MAX)
}

/// Spawn a userspace task on an explicit dense CPU.
pub fn spawn_user_thread_on_cpu(
    name: &[u8; 32],
    process: Arc<Process>,
    entry_point: u64,
    user_rsp: u64,
    cr3: u64,
    cpu: usize,
) -> Option<u64> {
    spawn_user_thread_on_cpu_ex(name, process, None, entry_point, user_rsp, 0, 0, cr3, cpu)
}

/// Spawn a user thread with initial register state and optional Thread object.
#[allow(clippy::too_many_arguments)]
pub fn spawn_user_thread_on_cpu_ex(
    name: &[u8; 32],
    process: Arc<Process>,
    thread: Option<Arc<huesos_object::Thread>>,
    entry_point: u64,
    user_rsp: u64,
    arg0: u64,
    fs_base: u64,
    cr3: u64,
    cpu: usize,
) -> Option<u64> {
    if cpu >= MAX_CPUS || !is_cpu_online(cpu) {
        return None;
    }
    if process.exit_code().is_some() {
        return None;
    }
    let (slot, generation) = TASK_SLOTS.allocate()?;
    let Some(id) = V2TaskId::new(slot, generation) else {
        let _ = TASK_SLOTS.free(slot);
        return None;
    };
    let _ = process.start();
    process.increment_active_threads();
    let task = Box::new(Task::new_user_with_thread(
        id.raw(),
        *name,
        Arc::clone(&process),
        thread,
        crate::process::user_entry_trampoline,
        cr3,
        fs_base,
    ));
    crate::process::queue_user_entry_ex(id.raw(), entry_point, user_rsp, arg0, fs_base);
    let Some(owner) = CpuIndex::new(cpu) else {
        crate::process::cancel_user_entry(id.raw());
        let _ = process.decrement_active_threads();
        let _ = TASK_SLOTS.free(slot);
        return None;
    };
    if TASK_DIRECTORY.publish(id, owner, slot).is_err() {
        crate::process::cancel_user_entry(id.raw());
        let _ = process.decrement_active_threads();
        let _ = TASK_SLOTS.free(slot);
        return None;
    }
    record_task(slot, Some(&task), cpu, 1);
    LIVE_TASK_COUNT.fetch_add(1, Ordering::AcqRel);

    if cpu == cpu_id() {
        let now_ns = monotonic_ns();
        let was_enabled = x86_64::instructions::interrupts::are_enabled();
        huesos_arch::interrupts::disable();
        let result = {
            let mut scheduler = PER_CPU_SCHEDULERS[cpu].lock();
            scheduler.insert_task(cpu, task, now_ns)
        };
        if let Err(task) = result {
            clear_task_identity(id.raw());
            crate::process::cancel_user_entry(id.raw());
            let _ = process.decrement_active_threads();
            drop(task);
            if was_enabled {
                huesos_arch::interrupts::enable();
            }
            return None;
        }
        if was_enabled {
            huesos_arch::interrupts::enable();
        }
    } else {
        if let Err(task) = place_pending_task(id, cpu, task) {
            clear_task_identity(id.raw());
            crate::process::cancel_user_entry(id.raw());
            let _ = process.decrement_active_threads();
            drop(task);
            return None;
        }
        if !publish_remote_operation(id, task_operations::SPAWN, cpu) {
            let pending = take_pending_task(id);
            clear_task_identity(id.raw());
            crate::process::cancel_user_entry(id.raw());
            let _ = process.decrement_active_threads();
            drop(pending);
            return None;
        }
    }
    Some(id.raw())
}

/// Exit the current userspace thread and switch away permanently.
pub fn exit_current_thread(code: i64) -> ! {
    huesos_arch::interrupts::disable();
    let cpu = cpu_id();
    let now_ns = monotonic_ns();
    let mut process_to_check = None;
    let mut thread_to_exit = None;
    let task_id = {
        let mut scheduler = PER_CPU_SCHEDULERS[cpu].lock();
        let Some(slot_index) = scheduler.current else {
            scheduler_fail_stop();
        };
        let id = scheduler.task(slot_index).map_or(0, |slot| slot.task.id);
        scheduler.mark_dead(id, slot_index, code, now_ns);
        if let Some(slot) = scheduler.task(slot_index) {
            if let TaskKind::User { process, thread } = &slot.task.kind {
                process_to_check = Some(Arc::clone(process));
                thread_to_exit = thread.as_ref().map(Arc::clone);
            }
        }
        id
    };
    let _ = task_id;
    if let Some(thread) = thread_to_exit {
        let _ = thread.set_exit_code(code);
    }
    if let Some(process) = process_to_check {
        let previous = process.decrement_active_threads();
        if previous <= 1 && process.set_exit_code(code) {
            record_process_exit(&process, code);
            huesos_object::collect_exited_process(process.koid());
            PROCESS_TEARDOWN.lock().push(process);
            REAP_PENDING.store(true, Ordering::Release);
        }
    }
    switch_away_from_finished(cpu)
}

/// Exit the current task; userspace exit terminates the complete Process.
pub fn exit_current_task(code: i64) -> ! {
    huesos_arch::interrupts::disable();
    let cpu = cpu_id();
    let is_user = {
        let scheduler = PER_CPU_SCHEDULERS[cpu].lock();
        scheduler
            .current
            .and_then(|index| scheduler.task(index))
            .is_some_and(|task| matches!(task.task.kind, TaskKind::User { .. }))
    };
    if is_user {
        terminate_current_process(code);
    }
    let now_ns = monotonic_ns();
    {
        let mut scheduler = PER_CPU_SCHEDULERS[cpu].lock();
        if let Some(slot_index) = scheduler.current {
            let id = scheduler.task(slot_index).map_or(0, |slot| slot.task.id);
            scheduler.mark_dead(id, slot_index, code, now_ns);
        }
    }
    switch_away_from_finished(cpu)
}

/// Terminate the calling Process and every sibling thread.
pub fn terminate_current_process(code: i64) -> ! {
    huesos_arch::interrupts::disable();
    let current_cpu = cpu_id();
    let process = {
        let scheduler = PER_CPU_SCHEDULERS[current_cpu].lock();
        scheduler
            .current
            .and_then(|index| scheduler.task(index))
            .and_then(|task| match &task.task.kind {
                TaskKind::User { process, .. } => Some(Arc::clone(process)),
                TaskKind::Kernel | TaskKind::Reaped => None,
            })
    };
    let Some(process) = process else {
        scheduler_fail_stop();
    };
    let _ = terminate_process(&process, code, current_cpu);
    switch_away_from_finished(current_cpu)
}

/// Terminate every task belonging to `process` without taking a remote
/// runqueue lock. KILL operations are consumed by each owner CPU.
pub fn terminate_process(process: &Arc<Process>, code: i64, current_cpu: usize) -> bool {
    let was_enabled = x86_64::instructions::interrupts::are_enabled();
    huesos_arch::interrupts::disable();
    if !process.set_exit_code(code) {
        if was_enabled {
            huesos_arch::interrupts::enable();
        }
        return false;
    }
    record_process_exit(process, code);
    let process_koid = process.koid();
    huesos_object::collect_exited_process(process_koid);
    for cell in TASK_RECORDS.iter() {
        let Some(record) = cell.load() else {
            continue;
        };
        if record.process_koid() != process_koid.0 {
            continue;
        }
        let Some(id) = V2TaskId::from_raw(record.task_id) else {
            continue;
        };
        let Some(location) = task_location(record.task_id) else {
            continue;
        };
        let cpu = location.owner.as_usize();
        KILL_EXIT_CODES[id.slot()].store(code, Ordering::Release);
        if cpu == cpu_id() {
            let now_ns = monotonic_ns();
            let mut scheduler = PER_CPU_SCHEDULERS[cpu].lock();
            scheduler.mark_dead(record.task_id, location.local_index as usize, code, now_ns);
        } else {
            let _ = publish_remote_operation(id, task_operations::KILL, cpu);
        }
    }
    huesos_object::clear_process_from_all_cpus(process_koid);
    PROCESS_TEARDOWN.lock().push(Arc::clone(process));
    REAP_PENDING.store(true, Ordering::Release);
    for cpu in 0..MAX_CPUS {
        if cpu != current_cpu && is_cpu_online(cpu) {
            queue_ipi(cpu);
        }
    }
    if was_enabled {
        huesos_arch::interrupts::enable();
    }
    true
}

/// Capability-checked syscall callback target: the syscall layer validated
/// WRITE rights before passing this KOID, so resolution here is identity-only.
pub fn terminate_process_by_koid(koid: Koid, code: i64) -> Result<(), huesos_abi::ErrorCode> {
    let process = huesos_object::lookup_process(koid).ok_or(huesos_abi::ErrorCode::BadHandle)?;
    let _ = terminate_process(&process, code, cpu_id());
    Ok(())
}

fn switch_away_from_finished(cpu: usize) -> ! {
    loop {
        let drained = CPU_INBOX[cpu].drain(|slot| process_inbox_task(cpu, slot));
        OBS_INBOX_DRAINS.fetch_add(drained as u64, Ordering::Relaxed);
        let now_ns = monotonic_ns();
        let result = {
            let mut scheduler = PER_CPU_SCHEDULERS[cpu].lock();
            scheduler.schedule(now_ns, false)
        };
        if let Some(decision) = result.decision {
            decision.environment.install();
            perform_context_switch(decision.target);
        }
        drop(result.charge_process);
        huesos_arch::interrupts::enable();
        huesos_arch::hlt();
        huesos_arch::interrupts::disable();
    }
}

static TASK_GRAVEYARD: RankedIrqSafeTicketLock<Option<TaskGraveyard<256>>> =
    RankedIrqSafeTicketLock::new(None, LockRank::REAPER);
static TASK_GRAVEYARD_EVICTIONS: AtomicU64 = AtomicU64::new(0);

fn record_process_exit(process: &Process, code: i64) {
    let Some(info) = process.exit_info() else {
        return;
    };
    {
        let mut yard = TASK_GRAVEYARD.lock();
        let graveyard = yard.get_or_insert_with(TaskGraveyard::new);
        let (_, outcome) =
            graveyard.record_exit_with_generation(info.koid, info.generation, code, global_ticks());
        if matches!(outcome, InsertOutcome::Evicted(_)) {
            TASK_GRAVEYARD_EVICTIONS.fetch_add(1, Ordering::Relaxed);
        }
    }
    if process.is_critical() {
        let name = process.name();
        crate::shutdown::note_critical_exit(&name, code);
    }
}

fn reap_observed_process_exits() {
    let mut yard = TASK_GRAVEYARD.lock();
    let Some(graveyard) = yard.as_mut() else {
        return;
    };
    let _ =
        graveyard.reap_waited(
            |koid, generation| match huesos_object::lookup_process(Koid(koid)) {
                Some(process) => process.observed_exit_generation(generation),
                None => true,
            },
        );
}

static REAP_PENDING: AtomicBool = AtomicBool::new(false);
static REAP_QUEUE: RankedIrqSafeTicketLock<Vec<u64>> =
    RankedIrqSafeTicketLock::new(Vec::new(), LockRank::REAPER);
// The task box owns a separately allocated stack; it stays boxed until the
// reaper drops it outside scheduler-owner critical sections.
#[allow(clippy::vec_box)]
static DEFERRED_TASK_DROPS: RankedIrqSafeTicketLock<Vec<Box<Task>>> =
    RankedIrqSafeTicketLock::new(Vec::new(), LockRank::REAPER);
static THREAD_EXIT_QUEUE: RankedIrqSafeTicketLock<Vec<(Arc<huesos_object::Thread>, i64)>> =
    RankedIrqSafeTicketLock::new(Vec::new(), LockRank::REAPER);
static PROCESS_TEARDOWN: RankedIrqSafeTicketLock<Vec<Arc<Process>>> =
    RankedIrqSafeTicketLock::new(Vec::new(), LockRank::REAPER);

fn enqueue_reap(id: u64) {
    let mut queue = REAP_QUEUE.lock();
    if !queue.contains(&id) {
        queue.push(id);
    }
    REAP_PENDING.store(true, Ordering::Release);
}

/// Service pending task/process teardown after subsystem locks are released.
pub fn reap_if_pending() {
    if REAP_PENDING.swap(false, Ordering::AcqRel) {
        reap_finished_tasks();
    }
    huesos_object::flush_pending_quota_notifications();
}

/// Reap only on the owner CPU; remote requests use the REAP inbox operation.
pub fn reap_finished_tasks() {
    let batch = {
        let mut queue = REAP_QUEUE.lock();
        core::mem::take(&mut *queue)
    };
    for id in batch {
        crate::process::cancel_user_entry(id);
        let Some(location) = task_location(id) else {
            continue;
        };
        let cpu = location.owner.as_usize();
        if cpu >= MAX_CPUS {
            continue;
        }
        if CURRENT_TASK_IDS[cpu].load(Ordering::Acquire) == id {
            continue;
        }
        if cpu == cpu_id() {
            let mut scheduler = PER_CPU_SCHEDULERS[cpu].lock();
            if let Some(task) = scheduler.reap_task(id, location.local_index as usize) {
                drop(scheduler);
                deferred_task_drop(task);
            }
        } else if let Some(task_id) = V2TaskId::from_raw(id) {
            let _ = publish_remote_operation(task_id, task_operations::REAP, cpu);
        }
    }

    let threads = {
        let mut queue = THREAD_EXIT_QUEUE.lock();
        core::mem::take(&mut *queue)
    };
    for (thread, code) in threads {
        let _ = thread.set_exit_code(code);
    }
    let dropped_tasks = {
        let mut queue = DEFERRED_TASK_DROPS.lock();
        core::mem::take(&mut *queue)
    };
    drop(dropped_tasks);

    let processes = {
        let mut queue = PROCESS_TEARDOWN.lock();
        core::mem::take(&mut *queue)
    };
    for process in processes {
        let koid = process.koid().0;
        let still_current = CURRENT_PROCESS_KOIDS
            .iter()
            .any(|current| current.load(Ordering::Acquire) == koid);
        if still_current {
            PROCESS_TEARDOWN.lock().push(process);
            REAP_PENDING.store(true, Ordering::Release);
        } else {
            crate::process::teardown_process(&process);
        }
    }
    reap_observed_process_exits();
}

#[cfg(test)]
mod task_id_tests {
    use super::*;

    fn replenish_deadline_on_unblock(
        now: u64,
        capacity: u64,
        period: u64,
        remaining_budget: &mut u64,
        deadline: &mut u64,
    ) {
        *deadline = now.saturating_add(period);
        *remaining_budget = capacity;
    }

    #[test]
    fn global_task_ids_do_not_encode_cpu_ownership() {
        let first = V2TaskId::new(10, 1).map_or(0, V2TaskId::raw);
        let second = V2TaskId::new(11, 1).map_or(0, V2TaskId::raw);
        assert_ne!(first, second);
        assert_eq!(V2TaskId::from_raw(first).map(V2TaskId::slot), Some(10));
        assert_eq!(V2TaskId::from_raw(first).map(V2TaskId::generation), Some(1));
        assert!(task_location(first).is_none());
    }

    #[test]
    fn deadline_replenishment_uses_nanoseconds_and_saturates() {
        let mut remaining = 5;
        let mut deadline = 30;
        replenish_deadline_on_unblock(500, 40, 100, &mut remaining, &mut deadline);
        assert_eq!(deadline, 600);
        assert_eq!(remaining, 40);
        replenish_deadline_on_unblock(u64::MAX, 1, 10, &mut remaining, &mut deadline);
        assert_eq!(deadline, u64::MAX);
    }

    #[test]
    fn partial_slice_accounting_advances_virtual_start_without_lag_refund() {
        let weight = huesos_sched::NICE_0_WEIGHT;
        let v0 = 1_000_000u128;
        let (mut finish, mut remaining_ns) = Scheduler::make_request(v0, FAIR_REQUEST_NS, weight);
        let mut start = v0;
        let elapsed = FAIR_REQUEST_NS / 2;
        let delta = virtual_delta(elapsed, weight).map_or(1, |d| d);
        remaining_ns -= elapsed;
        start = start.saturating_add(delta).min(finish);
        let (new_finish, _) = Scheduler::make_request(start, remaining_ns, weight);
        finish = new_finish;

        let job_vtime = v0.saturating_add(delta);
        assert_eq!(signed_delta(job_vtime, start), 0);
        assert!(finish > start);
    }

    #[test]
    fn interactive_spawn_credit_makes_new_fair_task_immediately_eligible() {
        let weight = huesos_sched::NICE_0_WEIGHT;
        let job_vtime = 50_000_000_000u128;
        let initial_slice = (FAIR_REQUEST_NS / 2).max(1);
        let credit = virtual_delta(initial_slice, weight).map_or(1, |d| d);
        let start = job_vtime.saturating_sub(credit);
        let (finish, _) = Scheduler::make_request(start, initial_slice, weight);
        let (hog_finish, _) = Scheduler::make_request(job_vtime, FAIR_REQUEST_NS, weight);
        assert!(start <= job_vtime);
        assert!(finish < hog_finish);
    }

    #[test]
    fn multi_thread_job_remains_root_queued_after_selecting_one_sibling() {
        let weight = huesos_sched::NICE_0_WEIGHT;
        let mut root_jobs: EevdfTree<MAX_JOB_QUEUES> = EevdfTree::new();
        let mut root_vtime = 0u128;
        let Some(job_id) = JobId::new(7) else {
            assert_eq!(0, 1);
            return;
        };
        let Some(mut job) = JobRunqueue::new(job_id, weight, 0) else {
            assert_eq!(0, 1);
            return;
        };
        let id_a = V2TaskId::new(1, 1).map_or(0, V2TaskId::raw);
        let id_b = V2TaskId::new(2, 1).map_or(0, V2TaskId::raw);
        let (finish_a, _) = Scheduler::make_request(0, FAIR_REQUEST_NS, weight);
        let (finish_b, _) = Scheduler::make_request(100, FAIR_REQUEST_NS, weight);
        assert!(job
            .threads
            .insert(
                EevdfKey {
                    virtual_start: 0,
                    task_id: id_a,
                },
                finish_a,
            )
            .is_ok());
        assert!(job
            .threads
            .insert(
                EevdfKey {
                    virtual_start: 100,
                    task_id: id_b,
                },
                finish_b,
            )
            .is_ok());
        job.fair_runnable = 2;

        let (root_finish, _) = Scheduler::make_request(job.root_start, FAIR_REQUEST_NS, job.weight);
        assert!(root_jobs
            .insert(
                EevdfKey {
                    virtual_start: job.root_start,
                    task_id: u64::from(job.id.raw()),
                },
                root_finish,
            )
            .is_ok());
        job.root_queued = true;

        assert!(matches!(
            root_jobs.pop_eligible(&mut root_vtime),
            Ok(Some(_))
        ));
        job.root_queued = false;
        let first_tid = match job.threads.pop_eligible(&mut job.virtual_time) {
            Ok(Some((key, _))) => key.task_id,
            _ => 0,
        };
        assert_eq!(first_tid, id_a);
        assert!(!job.threads.is_empty() && job.fair_runnable != 0);

        // Re-insert the job while the sibling thread remains queued so the
        // next `pick_next` selects `id_b` without stalling until `id_a` blocks.
        assert!(root_jobs
            .insert(
                EevdfKey {
                    virtual_start: job.root_start,
                    task_id: u64::from(job.id.raw()),
                },
                root_finish,
            )
            .is_ok());
        job.root_queued = true;
        assert!(job.root_queued);
        assert!(matches!(
            root_jobs.pop_eligible(&mut root_vtime),
            Ok(Some(_))
        ));
        let second_tid = match job.threads.pop_eligible(&mut job.virtual_time) {
            Ok(Some((key, _))) => key.task_id,
            _ => 0,
        };
        assert_eq!(second_tid, id_b);
    }
}
