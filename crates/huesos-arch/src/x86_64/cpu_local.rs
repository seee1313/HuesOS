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
        }
    }
}

static_assertions::const_assert_eq!(core::mem::offset_of!(CpuLocal, user_rsp), 40);
static_assertions::const_assert_eq!(core::mem::offset_of!(CpuLocal, kernel_rsp), 48);
static_assertions::const_assert_eq!(core::mem::size_of::<CpuLocal>(), 56);

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
            "mov {out}, gs:[{offset}]",
            out = out(reg) id,
            offset = in(reg) core::mem::size_of::<*mut CpuLocal>(),
            options(nomem, nostack),
        );
    }
    id
}
