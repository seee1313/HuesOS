//! Task (thread) representation: kernel threads and userspace (ring3)
//! processes/threads, backed by guard-paged `NX` kernel stacks and 64-byte-
//! aligned per-task SIMD save areas.

use alloc::alloc::{alloc_zeroed, dealloc, Layout};
use alloc::sync::Arc;
use alloc::vec::Vec;
use huesos_arch::context_switch::{init_simd_save_area, Context};
use huesos_arch::VirtAddr;
use huesos_object::Process;

/// Stack size for a kernel thread (64 KiB).
pub const KERNEL_STACK_SIZE: usize = 4096 * 16;
/// Stack size for a userspace thread's kernel-side stack (used for
/// interrupts/syscalls while running in ring0 on behalf of that thread).
pub const USER_KERNEL_STACK_SIZE: usize = 4096 * 16;

/// Guard-paged `NO_EXECUTE` kernel stack (`SMP_V2.md` §10), with a heap
/// fallback when running host unit tests before kernel paging is initialized.
pub struct KernelStack {
    guarded_base: u64,
    guarded_len: usize,
    fallback: Vec<u8>,
}

impl KernelStack {
    /// Empty sentinel stack for `idle` and `reaped` tasks (`top() == 0`).
    pub const fn empty() -> Self {
        Self {
            guarded_base: 0,
            guarded_len: 0,
            fallback: Vec::new(),
        }
    }

    /// Allocate a `size`-byte kernel stack, preferring a hardware-guard-paged
    /// `KERNEL_RW` (`NX`) slot in the private kernel stack arena.
    pub fn allocate(size: usize) -> Self {
        if size == 0 {
            return Self::empty();
        }
        #[cfg(not(test))]
        if let Some((base, len)) = huesos_arch::paging::alloc_guarded_kernel_stack(size) {
            return Self {
                guarded_base: base,
                guarded_len: len,
                fallback: Vec::new(),
            };
        }
        Self {
            guarded_base: 0,
            guarded_len: 0,
            fallback: alloc::vec![0u8; size],
        }
    }

    /// True when this task owns no stack allocation (`idle` / `reaped`).
    pub fn is_empty(&self) -> bool {
        self.guarded_len == 0 && self.fallback.is_empty()
    }

    /// Exclusive top-of-stack virtual address (`0` when empty).
    pub fn top(&self) -> u64 {
        if self.guarded_len != 0 {
            self.guarded_base.saturating_add(self.guarded_len as u64)
        } else if self.fallback.is_empty() {
            0
        } else {
            (self.fallback.as_ptr() as u64).saturating_add(self.fallback.len() as u64)
        }
    }

    fn top_mut_ptr(&mut self) -> *mut u8 {
        if self.guarded_len != 0 {
            self.guarded_base.saturating_add(self.guarded_len as u64) as *mut u8
        } else {
            self.fallback.as_mut_ptr().wrapping_add(self.fallback.len())
        }
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        if self.guarded_len != 0 {
            huesos_arch::paging::free_guarded_kernel_stack(self.guarded_base, self.guarded_len);
            self.guarded_base = 0;
            self.guarded_len = 0;
        }
    }
}

/// 64-byte-aligned userspace `XSAVE64` / `FXSAVE64` register save buffer.
pub struct SimdState {
    addr: usize,
    bytes: usize,
}

impl SimdState {
    /// Empty state for pure kernel/idle tasks (`addr == 0`).
    pub const fn empty() -> Self {
        Self { addr: 0, bytes: 0 }
    }

    /// Allocate and reset a 64-byte-aligned SIMD save buffer for a user task.
    pub fn new_user() -> Self {
        let bytes = huesos_arch::cpu::simd_save_bytes().clamp(512, 4096);
        let Ok(layout) = Layout::from_size_align(bytes, 64) else {
            return Self::empty();
        };
        let ptr = unsafe {
            let raw = alloc_zeroed(layout);
            if !raw.is_null() {
                init_simd_save_area(core::slice::from_raw_parts_mut(raw, bytes));
            }
            raw
        };
        if ptr.is_null() {
            Self::empty()
        } else {
            Self {
                addr: ptr as usize,
                bytes,
            }
        }
    }

    /// Virtual address of the 64-byte-aligned save buffer, or `0` if absent.
    pub const fn addr(&self) -> u64 {
        self.addr as u64
    }
}

impl Drop for SimdState {
    fn drop(&mut self) {
        if self.addr != 0 && self.bytes != 0 {
            if let Ok(layout) = Layout::from_size_align(self.bytes, 64) {
                unsafe {
                    dealloc(self.addr as *mut u8, layout);
                }
            }
            self.addr = 0;
            self.bytes = 0;
        }
    }
}

/// What kind of execution context this task represents.
pub enum TaskKind {
    /// A task that only ever runs in ring0 (kernel code).
    Kernel,
    /// A task that runs userspace code in ring3, associated with a
    /// [`Process`] and its own address space.
    User {
        /// Owning process (address space + handle table).
        process: Arc<Process>,
        /// Optional userspace `Thread` object for intra-process thread lifecycle.
        thread: Option<Arc<huesos_object::Thread>>,
    },
    /// Finished task after stack and process ownership have been reclaimed.
    Reaped,
}

/// A schedulable task — execution context with its own stack and SIMD state.
pub struct Task {
    /// Task id.
    pub id: u64,
    /// Task name.
    pub name: [u8; 32],
    /// CPU context (callee-saved + RIP/RSP/RFLAGS/CR3/TLS/SIMD).
    pub context: Context,
    /// Guard-paged kernel stack (used directly for kernel tasks, or as RSP0 /
    /// syscall stack for user tasks).
    pub kernel_stack: KernelStack,
    /// Per-task userspace SIMD (`XSAVE64`/`FXSAVE64`) buffer.
    pub simd_state: SimdState,
    /// What kind of task this is.
    pub kind: TaskKind,
    /// Set once the task has exited; the scheduler skips finished tasks.
    pub finished: core::sync::atomic::AtomicBool,
    /// Set while the task is parked on a wait queue (blocking syscall).
    pub blocked: core::sync::atomic::AtomicBool,
    /// Wake arriving before the task completes the enqueue-to-park handshake.
    pub wake_pending: core::sync::atomic::AtomicBool,
    /// True until the first userspace-entry trampoline consumes this task's
    /// pending RIP/RSP record. Migration skips tasks while `startup_pending` is true.
    pub startup_pending: core::sync::atomic::AtomicBool,
    /// Scheduling policy.
    pub sched_policy: crate::scheduler::SchedPolicy,
    /// Explicit Scheduler v2 lifecycle state.
    pub lifecycle: huesos_sched::TaskLifecycle,
    /// Monotonic wait-epoch incremented on every block attempt so stale wakes are rejected.
    pub wait_epoch: core::sync::atomic::AtomicU32,
    /// Resource/Job domain this task is charged to. Defaults to the root job.
    pub job_id: huesos_sched::job::JobId,
    /// Nested preemption/migration guards carried with this Task across CPU switches.
    pub execution_guards: huesos_sched::ExecutionGuards,
    /// Allowed dense CPU mask (`SMP_V2.md` §13); enforced across spawn & migration.
    pub allowed_cpus: huesos_sched::CpuMask,
    /// Timestamp (`monotonic_ns`) of the most recent cross-CPU migration.
    pub last_migrated_ns: u64,
}

impl Task {
    /// Create the idle task (no real stack, never preempted away from).
    pub fn new_idle(id: u64, name: [u8; 32]) -> Self {
        Self {
            id,
            name,
            context: Context::zero_with_cr3(current_cr3()),
            kernel_stack: KernelStack::empty(),
            simd_state: SimdState::empty(),
            kind: TaskKind::Kernel,
            finished: core::sync::atomic::AtomicBool::new(false),
            blocked: core::sync::atomic::AtomicBool::new(false),
            wake_pending: core::sync::atomic::AtomicBool::new(false),
            startup_pending: core::sync::atomic::AtomicBool::new(false),
            sched_policy: crate::scheduler::SchedPolicy::default_fair(),
            lifecycle: huesos_sched::TaskLifecycle::new(),
            wait_epoch: core::sync::atomic::AtomicU32::new(0),
            execution_guards: huesos_sched::ExecutionGuards::new(),
            job_id: huesos_sched::job::JobId::ROOT,
            allowed_cpus: huesos_sched::CpuMask::full(),
            last_migrated_ns: 0,
        }
    }

    /// Create an inert reaped placeholder for an emptied scheduler slot.
    pub fn new_reaped(id: u64) -> Self {
        Self {
            id,
            name: *b"reaped\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            context: Context::zero_with_cr3(current_cr3()),
            kernel_stack: KernelStack::empty(),
            simd_state: SimdState::empty(),
            kind: TaskKind::Reaped,
            finished: core::sync::atomic::AtomicBool::new(true),
            blocked: core::sync::atomic::AtomicBool::new(false),
            wake_pending: core::sync::atomic::AtomicBool::new(false),
            startup_pending: core::sync::atomic::AtomicBool::new(false),
            sched_policy: crate::scheduler::SchedPolicy::default_fair(),
            lifecycle: huesos_sched::TaskLifecycle::new(),
            wait_epoch: core::sync::atomic::AtomicU32::new(0),
            execution_guards: huesos_sched::ExecutionGuards::new(),
            job_id: huesos_sched::job::JobId::ROOT,
            allowed_cpus: huesos_sched::CpuMask::empty(),
            last_migrated_ns: 0,
        }
    }

    /// Create a kernel task that starts executing `entry`.
    pub fn new_kernel(id: u64, name: [u8; 32], entry: extern "C" fn() -> !) -> Self {
        let mut stack = KernelStack::allocate(KERNEL_STACK_SIZE);
        let stack_top = stack.top_mut_ptr();
        let cr3 = current_cr3();
        let context = unsafe {
            let ret_slot = (stack_top as *mut u64).sub(1);
            *ret_slot = thread_exit as *const () as u64;
            Context::new(entry, stack_top.sub(8), cr3)
        };
        Self {
            id,
            name,
            context,
            kernel_stack: stack,
            simd_state: SimdState::empty(),
            kind: TaskKind::Kernel,
            finished: core::sync::atomic::AtomicBool::new(false),
            blocked: core::sync::atomic::AtomicBool::new(false),
            wake_pending: core::sync::atomic::AtomicBool::new(false),
            startup_pending: core::sync::atomic::AtomicBool::new(false),
            sched_policy: crate::scheduler::SchedPolicy::default_fair(),
            lifecycle: huesos_sched::TaskLifecycle::new(),
            wait_epoch: core::sync::atomic::AtomicU32::new(0),
            execution_guards: huesos_sched::ExecutionGuards::new(),
            job_id: huesos_sched::job::JobId::ROOT,
            allowed_cpus: huesos_sched::CpuMask::full(),
            last_migrated_ns: 0,
        }
    }

    /// Create a userspace task.
    pub fn new_user(
        id: u64,
        name: [u8; 32],
        process: Arc<Process>,
        entry_trampoline: extern "C" fn() -> !,
        cr3: u64,
    ) -> Self {
        Self::new_user_with_thread(id, name, process, None, entry_trampoline, cr3, 0)
    }

    /// Create a userspace task optionally bound to a [`huesos_object::Thread`]
    /// and an initial `MSR_FS_BASE`.
    pub fn new_user_with_thread(
        id: u64,
        name: [u8; 32],
        process: Arc<Process>,
        thread: Option<Arc<huesos_object::Thread>>,
        entry_trampoline: extern "C" fn() -> !,
        cr3: u64,
        fs_base: u64,
    ) -> Self {
        let mut stack = KernelStack::allocate(USER_KERNEL_STACK_SIZE);
        let simd_state = SimdState::new_user();
        let stack_top = stack.top_mut_ptr();
        let mut context = unsafe {
            let ret_slot = (stack_top as *mut u64).sub(1);
            *ret_slot = thread_exit as *const () as u64;
            Context::new(entry_trampoline, stack_top.sub(8), cr3)
        };
        context.fs_base = fs_base;
        context.simd_addr = simd_state.addr();
        let job_id = crate::scheduler::resolve_sched_job_id(process.job().koid());
        let allowed_cpus = huesos_sched::CpuMask::from_words(process.affinity_mask_words());
        Self {
            id,
            name,
            context,
            kernel_stack: stack,
            simd_state,
            kind: TaskKind::User { process, thread },
            finished: core::sync::atomic::AtomicBool::new(false),
            blocked: core::sync::atomic::AtomicBool::new(false),
            wake_pending: core::sync::atomic::AtomicBool::new(false),
            startup_pending: core::sync::atomic::AtomicBool::new(true),
            sched_policy: crate::scheduler::SchedPolicy::default_fair(),
            lifecycle: huesos_sched::TaskLifecycle::new(),
            wait_epoch: core::sync::atomic::AtomicU32::new(0),
            execution_guards: huesos_sched::ExecutionGuards::new(),
            job_id,
            allowed_cpus,
            last_migrated_ns: 0,
        }
    }

    /// Top-of-stack address for this task's kernel stack (`0` for idle/reaped).
    pub fn kernel_stack_top(&self) -> u64 {
        self.kernel_stack.top()
    }
}

fn current_cr3() -> u64 {
    use x86_64::registers::control::Cr3;
    Cr3::read_raw().0.start_address().as_u64()
}

/// Default landing pad when a kernel thread returns.
extern "C" fn thread_exit() -> ! {
    loop {
        huesos_arch::hlt();
    }
}

/// Silence unused import warning when VirtAddr isn't otherwise referenced.
#[allow(dead_code)]
fn _assert_virtaddr_reexport(_: VirtAddr) {}
