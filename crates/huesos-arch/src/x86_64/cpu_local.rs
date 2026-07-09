//! Per-CPU local variables via the GS segment base (x86_64).
//!
//! Each CPU stores a pointer to its own `CpuLocal` structure at GS_BASE.
//! Access is via `gs:[offset]` which is fast (no MMIO, no locking).

use core::arch::asm;

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

static mut CPU_LOCALS: [CpuLocal; MAX_CPUS] = [CpuLocal::empty(); MAX_CPUS];
static CPU_LOCAL_NEXT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Allocate and initialize a `CpuLocal` for the current CPU.
/// Returns a mutable reference valid for `'static`.
///
/// # Safety
/// Must be called exactly once per CPU, before `init_gs_base`.
pub unsafe fn alloc_cpu_local(lapic_id: u32) -> &'static mut CpuLocal {
    let idx = CPU_LOCAL_NEXT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    assert!(idx < MAX_CPUS, "too many CPUs");
    let ptr = &raw mut CPU_LOCALS[idx];
    unsafe {
        (*ptr).self_ptr = ptr;
        (*ptr).lapic_id = lapic_id;
    }
    unsafe { &mut *ptr }
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
