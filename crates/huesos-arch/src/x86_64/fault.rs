//! Architecture exception handoff between x86_64 and the kernel policy layer.

use core::sync::atomic::{AtomicUsize, Ordering};

/// CPU exception classes handled by the process-fault policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultKind {
    /// Divide error (#DE).
    DivideError,
    /// Invalid opcode (#UD).
    InvalidOpcode,
    /// General protection fault (#GP).
    GeneralProtection,
    /// Page fault (#PF).
    PageFault,
    /// Alignment check (#AC).
    AlignmentCheck,
    /// Double fault (#DF), always fatal to the kernel.
    DoubleFault,
}

impl FaultKind {
    /// Short stable name suitable for panic and serial diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DivideError => "DIVIDE ERROR",
            Self::InvalidOpcode => "INVALID OPCODE",
            Self::GeneralProtection => "GENERAL PROTECTION FAULT",
            Self::PageFault => "PAGE FAULT",
            Self::AlignmentCheck => "ALIGNMENT CHECK",
            Self::DoubleFault => "DOUBLE FAULT",
        }
    }
}

/// Register state supplied by an x86 exception frame.
#[derive(Clone, Copy, Debug)]
pub struct FaultInfo {
    /// Exception class.
    pub kind: FaultKind,
    /// Faulting instruction pointer.
    pub instruction_pointer: u64,
    /// Stack pointer at the interrupted privilege level.
    pub stack_pointer: u64,
    /// Saved RFLAGS.
    pub rflags: u64,
    /// Saved code-segment selector.
    pub code_segment: u64,
    /// Architecture error code, or zero for exceptions without one.
    pub error_code: u64,
    /// Faulting linear address for #PF, zero for other exceptions.
    pub fault_address: u64,
}

impl FaultInfo {
    /// Whether the exception originated at CPL3.
    pub const fn from_userspace(self) -> bool {
        self.code_segment & 3 == 3
    }
}

/// Kernel callback used for recoverable process termination.
pub type UserFaultHandler = fn(FaultInfo) -> !;
/// Kernel callback used for fatal ring-0 diagnostics.
pub type KernelFaultHandler = fn(FaultInfo) -> !;
/// Kernel callback consulted before a fatal ring-0 fault, to decide whether
/// the fault is one of a bounded set of validated user-copy sites that can
/// be recovered by resuming at `fixup_rip` (an `Err(EFAULT)` return path)
/// instead of panicking the kernel.
///
/// The hook must be effectively pure with respect to the fault: it may only
/// consult the extable it owns. It must not allocate, take a blocking lock,
/// or perform I/O. Returning `None` preserves the historical fatal-panic
/// behavior — deleting the hook is therefore always a safe rollback.
pub type KernelFaultRecoverHook = fn(FaultInfo) -> Option<u64>;

static USER_HANDLER: AtomicUsize = AtomicUsize::new(0);
static KERNEL_HANDLER: AtomicUsize = AtomicUsize::new(0);
static KERNEL_RECOVER_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Register the ring-3 fault policy callback.
pub fn set_user_fault_handler(handler: UserFaultHandler) {
    USER_HANDLER.store(handler as usize, Ordering::Release);
}

/// Register the fatal ring-0 fault callback.
pub fn set_kernel_fault_handler(handler: KernelFaultHandler) {
    KERNEL_HANDLER.store(handler as usize, Ordering::Release);
}

/// Register the recoverable-copy fixup hook. The hook is consulted **only**
/// for ring-0 faults, **only** by [`try_kernel_recover`], and is otherwise
/// invisible. Leaving it unset preserves pre-hook behavior exactly.
pub fn set_kernel_recover_hook(hook: KernelFaultRecoverHook) {
    KERNEL_RECOVER_HOOK.store(hook as usize, Ordering::Release);
}

/// Consult the registered recoverable-copy hook, if any. Returns
/// `Some(fixup_rip)` when a covering extable entry exists and the CPU
/// should resume at that address instead of taking the fatal path.
///
/// The IDT layer calls this only for **CPL0** faults and only before
/// [`kernel_fault`]. `info.instruction_pointer` is the faulting RIP.
pub fn try_kernel_recover(info: FaultInfo) -> Option<u64> {
    if info.from_userspace() {
        return None;
    }
    let hook = KERNEL_RECOVER_HOOK.load(Ordering::Acquire);
    if hook == 0 {
        return None;
    }
    // SAFETY: only `set_kernel_recover_hook` writes this value, from a
    // function pointer with exactly this signature.
    let hook: KernelFaultRecoverHook = unsafe { core::mem::transmute(hook) };
    hook(info)
}

/// Hand a ring-3 exception to the kernel process manager.
pub fn user_fault(info: FaultInfo) -> ! {
    let handler = USER_HANDLER.load(Ordering::Acquire);
    if handler != 0 {
        // SAFETY: only `set_user_fault_handler` writes this value, from a
        // function pointer with exactly this signature.
        let handler: UserFaultHandler = unsafe { core::mem::transmute(handler) };
        handler(info);
    }
    emergency_halt("user fault handler unavailable\n")
}

/// Hand a fatal ring-0 exception to the kernel panic subsystem.
pub fn kernel_fault(info: FaultInfo) -> ! {
    let handler = KERNEL_HANDLER.load(Ordering::Acquire);
    if handler != 0 {
        // SAFETY: only `set_kernel_fault_handler` writes this value, from a
        // function pointer with exactly this signature.
        let handler: KernelFaultHandler = unsafe { core::mem::transmute(handler) };
        handler(info);
    }
    emergency_halt("kernel fault handler unavailable\n")
}

fn emergency_halt(message: &str) -> ! {
    crate::serial::emergency_write("\nHuesOS fatal exception: ");
    crate::serial::emergency_write(message);
    crate::interrupts::disable();
    loop {
        crate::hlt();
    }
}
