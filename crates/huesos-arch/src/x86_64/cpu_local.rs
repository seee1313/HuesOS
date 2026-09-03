//! Per-CPU local variables via the GS segment base (x86_64).
//!
//! Each CPU stores a pointer to its own [`CpuLocal`] structure at `GS_BASE`.
//! Access is a fixed-offset `gs:` load, requiring no MMIO or shared lock.
//!
//! ## Ownership and initialization
//!
//! A global atomic index assigns each static slot exactly once. The assigned
//! CPU is the sole writer of ordinary per-CPU fields; cross-CPU coordination
//! uses separate atomics/IPIs. Storage never moves, so pointers installed in
//! MSRs, TSS setup, syscall assembly, and scheduler code remain valid forever.
//!
//! Reading GS before [`init_gs_base`] is a caller invariant and therefore an
//! unsafe operation. Safe higher layers only query CPU-local state after early
//! CPU initialization has completed.

use core::arch::asm;
use core::cell::UnsafeCell;

/// Maximum CPUs supported by the cpu-local array.
pub const MAX_CPUS: usize = 64;

/// Per-CPU data. Must be `#[repr(C)]` so offsets are stable for inline asm.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpuLocal {
    /// Self-pointer at offset 0 — allows `mov %gs:0, %rax` to recover the struct.
    pub self_ptr: *mut CpuLocal,
    /// LAPIC ID of this CPU (offset 8).
    pub lapic_id: u32,
    /// Padding to align current_task_id to 16-byte boundary (offset 12).
    pub _padding: u32,
    /// Current task ID (updated by scheduler on context switch, offset 16).
    pub current_task_id: u64,
    /// Pointer to this CPU's scheduler (kernel-managed, offset 24).
    pub scheduler: *mut (),
    /// Pointer to this CPU's GDT/TSS bundle (offset 32).
    pub gdt: *mut (),
    /// Scratch space for user RSP during syscall (offset 40).
    pub user_rsp: u64,
    /// Kernel RSP for syscall handling (offset 48).
    pub kernel_rsp: u64,
    /// Index of this CPU's runtime lock-rank tracker (offset 56).
    pub rank_tracker_index: usize,
    /// Scheduler-owned pointer to the running Task's nested execution guards
    /// (offset 64). Before the first Task is installed this names
    /// `bootstrap_guards` in the same CpuLocal slot.
    pub execution_guards: *mut huesos_sched::ExecutionGuards,
    /// Early-boot execution state used before Scheduler v2 publishes a Task.
    pub bootstrap_guards: huesos_sched::ExecutionGuards,
}

impl CpuLocal {
    /// Construct an unpublished slot before a CPU claims it.
    pub const fn empty() -> Self {
        Self {
            self_ptr: core::ptr::null_mut(),
            lapic_id: 0,
            _padding: 0,
            current_task_id: 0,
            scheduler: core::ptr::null_mut(),
            gdt: core::ptr::null_mut(),
            user_rsp: 0,
            kernel_rsp: 0,
            rank_tracker_index: 0,
            execution_guards: core::ptr::null_mut(),
            bootstrap_guards: huesos_sched::ExecutionGuards::new(),
        }
    }
}

static_assertions::const_assert_eq!(core::mem::offset_of!(CpuLocal, user_rsp), 40);
static_assertions::const_assert_eq!(core::mem::offset_of!(CpuLocal, kernel_rsp), 48);
static_assertions::const_assert_eq!(core::mem::offset_of!(CpuLocal, rank_tracker_index), 56);
static_assertions::const_assert_eq!(core::mem::offset_of!(CpuLocal, execution_guards), 64);
static_assertions::const_assert_eq!(core::mem::offset_of!(CpuLocal, bootstrap_guards), 72);
static_assertions::const_assert_eq!(core::mem::size_of::<CpuLocal>(), 80);

struct CpuLocalStorage(UnsafeCell<[CpuLocal; MAX_CPUS]>);

// SAFETY: CPU_LOCAL_NEXT hands each array element to exactly one CPU, once,
// before that CPU publishes its pointer through GS_BASE. No element is ever
// reallocated or handed to another writer, so cross-CPU mutable aliasing is
// excluded by the atomic allocation protocol.
unsafe impl Sync for CpuLocalStorage {}

static CPU_LOCALS: CpuLocalStorage =
    CpuLocalStorage(UnsafeCell::new([CpuLocal::empty(); MAX_CPUS]));
static CPU_LOCAL_NEXT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Allocate and initialize a `CpuLocal` for the current CPU.
/// Returns a mutable reference valid for `'static`.
///
/// # Safety
/// Must be called exactly once per CPU, before `init_gs_base`.
pub unsafe fn alloc_cpu_local(lapic_id: u32) -> &'static mut CpuLocal {
    let index = CPU_LOCAL_NEXT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    assert!(index < MAX_CPUS, "too many CPUs");
    // SAFETY: fetch_add returned a unique index and the backing array is
    // static, pinned storage. This is the only mutable reference ever created
    // for this element.
    let pointer = unsafe { core::ptr::addr_of_mut!((*CPU_LOCALS.0.get())[index]) };
    unsafe {
        (*pointer).self_ptr = pointer;
        (*pointer).lapic_id = lapic_id;
        (*pointer).rank_tracker_index = index;
        (*pointer).execution_guards = core::ptr::addr_of_mut!((*pointer).bootstrap_guards);
        &mut *pointer
    }
}

/// Write `GS_BASE` MSR (0xC000_0101) with the address of this CPU's `CpuLocal`.
///
/// # Safety
/// Must be called exactly once per CPU before any `cpu_local()` access.
pub unsafe fn init_gs_base(ptr: *mut CpuLocal) {
    let addr = ptr as u64;
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") 0xC000_0101u32,
            in("edx") (addr >> 32) as u32,
            in("eax") addr as u32,
            options(nomem, nostack),
        );
    }
}

/// Get the `CpuLocal` pointer for the current CPU.
///
/// # Safety
/// `init_gs_base` must have been called on this CPU.
pub unsafe fn cpu_local_ptr() -> *mut CpuLocal {
    let ptr: *mut CpuLocal;
    unsafe {
        asm!(
            "mov {out}, gs:[0]",
            out = out(reg) ptr,
            options(nomem, nostack),
        );
    }
    ptr
}

/// Convenience: read the LAPIC ID from the current CPU's locals.
///
/// # Safety
/// `init_gs_base` must have been called on this CPU.
pub unsafe fn current_lapic_id() -> u32 {
    // offset of `lapic_id` inside CpuLocal = size_of::<*mut CpuLocal>()
    let id: u32;
    unsafe {
        asm!(
            "mov {out:e}, gs:[{offset}]",
            out = out(reg) id,
            offset = in(reg) core::mem::size_of::<*mut CpuLocal>(),
            options(nomem, nostack),
        );
    }
    id
}

/// Return the current CPU's dense scheduler/index value.
///
/// Unlike LAPIC IDs, this is allocated densely in `0..MAX_CPUS` and is
/// therefore safe to use for per-CPU arrays, scheduler slots, task IDs, and
/// object current-process state. Sparse or high APIC IDs are deliberately not
/// used as array indexes.
///
/// # Safety
/// `init_gs_base` must have been called on this CPU.
pub unsafe fn current_cpu_index() -> usize {
    let index: usize;
    unsafe {
        asm!(
            "mov {out}, gs:[{offset}]",
            out = out(reg) index,
            offset = const core::mem::offset_of!(CpuLocal, rank_tracker_index),
            options(nomem, nostack, preserves_flags),
        );
    }
    index
}

/// Return the current CPU's unique lock-rank tracker index.
///
/// # Safety
/// `init_gs_base` must have been called on this CPU.
pub unsafe fn current_rank_tracker_index() -> usize {
    unsafe { current_cpu_index() }
}

/// Mutate the running Task's execution guards while local interrupts are
/// briefly disabled. Preemption/migration guards use this operation so timer
/// or reschedule IRQs never observe a torn nesting transition.
///
/// The Scheduler installs a Task-owned guard pointer before switching to it;
/// early boot uses the CpuLocal-embedded bootstrap value.
pub fn update_current_execution_guards<R>(
    operation: impl FnOnce(&mut huesos_sched::ExecutionGuards) -> Result<R, huesos_sched::GuardError>,
) -> Result<R, huesos_sched::GuardError> {
    let was_enabled = x86_64::instructions::interrupts::are_enabled();
    x86_64::instructions::interrupts::disable();
    // SAFETY: every caller runs after GS initialization. Interrupt masking
    // prevents a local context switch while the Task-owned pointer is loaded
    // and mutated. Scheduler v2 never reclaims a Task while it is current.
    let result = unsafe {
        let local = cpu_local_ptr();
        operation(&mut *(*local).execution_guards)
    };
    if was_enabled {
        x86_64::instructions::interrupts::enable();
    }
    result
}

/// Snapshot the running Task's execution nesting state.
pub fn current_execution_guards() -> huesos_sched::ExecutionGuards {
    let was_enabled = x86_64::instructions::interrupts::are_enabled();
    x86_64::instructions::interrupts::disable();
    // SAFETY: same ownership and interrupt contract as
    // [`update_current_execution_guards`].
    let guards = unsafe {
        let local = cpu_local_ptr();
        *(*local).execution_guards
    };
    if was_enabled {
        x86_64::instructions::interrupts::enable();
    }
    guards
}

/// Install the guard storage belonging to the Task about to run on this CPU.
///
/// # Safety
///
/// `guards` must remain valid and uniquely scheduler-owned while that Task is
/// current. Local interrupts must be disabled and no context switch may occur
/// between this call and switching to the corresponding Task context.
pub unsafe fn install_execution_guards(guards: *mut huesos_sched::ExecutionGuards) {
    // SAFETY: the caller owns the pointer lifetime and switch ordering.
    unsafe {
        (*cpu_local_ptr()).execution_guards = guards;
    }
}

/// Translate a dense CPU index back to the LAPIC ID used for IPIs.
///
/// Returns `None` for an index that has not been allocated yet. The BSP/AP
/// bring-up path initializes `lapic_id` before a CPU is marked online, so
/// scheduler users that consult this after `is_cpu_online(index)` see a stable
/// value.
pub fn lapic_id_for_index(index: usize) -> Option<u32> {
    if index >= CPU_LOCAL_NEXT.load(core::sync::atomic::Ordering::SeqCst) || index >= MAX_CPUS {
        return None;
    }
    // SAFETY: indices below CPU_LOCAL_NEXT have been uniquely assigned and the
    // slot storage is static. Reading the immutable-after-init LAPIC ID is safe
    // for IPI routing.
    let locals = unsafe { &*CPU_LOCALS.0.get() };
    Some(locals[index].lapic_id)
}
