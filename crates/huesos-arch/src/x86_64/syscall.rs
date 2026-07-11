//! Fast syscall entry (`syscall`/`sysret`) plumbing.
//!
//! Userspace invokes syscalls with the `syscall` instruction. The CPU
//! switches to ring0 using CS/SS from the `STAR` MSR, jumps to the address in
//! `LSTAR`, and masks RFLAGS per `SFMASK`. We save the user context, call
//! into the architecture-independent dispatcher, restore, and `sysret` back.

use core::arch::global_asm;
use core::sync::atomic::{AtomicUsize, Ordering};
use x86_64::registers::control::{Efer, EferFlags};
use x86_64::registers::model_specific::{LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;

/// Raw register snapshot for a syscall, passed to the Rust-level dispatcher.
///
/// Field order must match what the assembly trampoline pushes/pops.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct SyscallFrame {
    /// Syscall number (from `rax` at entry).
    pub num: u64,
    /// Argument 1 (`rdi`).
    pub arg1: u64,
    /// Argument 2 (`rsi`).
    pub arg2: u64,
    /// Argument 3 (`rdx`).
    pub arg3: u64,
    /// Argument 4 (`r10`, since `rcx` is clobbered by `syscall`).
    pub arg4: u64,
    /// Argument 5 (`r8`).
    pub arg5: u64,
    /// User RIP to resume at (saved into `rcx` by `syscall`).
    pub user_rip: u64,
    /// User RFLAGS to restore (saved into `r11` by `syscall`).
    pub user_rflags: u64,
    /// User RSP, saved/restored manually since `syscall` doesn't touch it.
    pub user_rsp: u64,
}

/// Type of the Rust-level syscall handler invoked by the asm trampoline.
pub type SyscallHandler = extern "C" fn(&mut SyscallFrame);

/// Global syscall handler function pointer, set by the kernel at init.
#[unsafe(no_mangle)]
pub static HUESOS_SYSCALL_HANDLER: AtomicUsize = AtomicUsize::new(0);

/// Register the Rust syscall dispatcher that the asm trampoline calls into.
///
/// Release ordering publishes all kernel initialization that precedes handler
/// installation before APs are allowed to issue syscalls. The assembly entry
/// performs a plain aligned load after the AP release gate; the value is never
/// changed again during normal operation.
pub fn set_handler(handler: SyscallHandler) {
    HUESOS_SYSCALL_HANDLER.store(handler as usize, Ordering::Release);
}

/// Set the kernel stack pointer used while servicing a syscall. Must be
/// updated by the scheduler whenever the current task changes.
pub fn set_kernel_stack(rsp: u64) {
    unsafe {
        let ptr = crate::cpu_local::cpu_local_ptr();
        (*ptr).kernel_rsp = rsp;
    }
}

/// Program STAR/LSTAR/SFMASK and enable `syscall`/`sysret`.
///
/// The four selectors must satisfy the `syscall`/`sysret` layout
/// constraints: `user_code` must be exactly one GDT slot (8 bytes) above
/// `user_data`, and `kernel_data` must be exactly one slot above
/// `kernel_code`. Our GDT is built in that order specifically to satisfy
/// this (see `gdt.rs`).
pub fn init(
    kernel_code: x86_64::structures::gdt::SegmentSelector,
    kernel_data: x86_64::structures::gdt::SegmentSelector,
    user_code: x86_64::structures::gdt::SegmentSelector,
    user_data: x86_64::structures::gdt::SegmentSelector,
) {
    Star::write(user_code, user_data, kernel_code, kernel_data)
        .expect("invalid STAR segment layout");

    LStar::write(x86_64::VirtAddr::new(
        syscall_entry as *const () as usize as u64,
    ));

    // Mask interrupts (IF) during syscall entry until we've swapped stacks.
    SFMask::write(RFlags::INTERRUPT_FLAG | RFlags::DIRECTION_FLAG | RFlags::TRAP_FLAG);

    unsafe {
        Efer::update(|flags| *flags |= EferFlags::SYSTEM_CALL_EXTENSIONS);
    }
}

unsafe extern "C" {
    /// Entry point installed in `LSTAR`. Never called directly from Rust.
    fn syscall_entry();
}

// The trampoline:
//  1. `syscall` has already put us in ring0 with RCX=user RIP, R11=user RFLAGS.
//  2. Stash the user RSP, switch to the kernel stack.
//  3. Push all argument/scratch registers into a `SyscallFrame` on the stack.
//  4. Call the Rust dispatcher with a pointer to that frame.
//  5. Pop everything back, restore user RSP, `sysretq`.
global_asm!(
    ".global syscall_entry",
    "syscall_entry:",
    // Swap to kernel stack, remembering the user one.
    "mov gs:[40], rsp",
    "mov rsp, gs:[48]",
    "push qword ptr gs:[40]", // user_rsp
    "push r11",               // user_rflags
    "push rcx",               // user_rip
    "push r8",                // arg5
    "push r10",               // arg4
    "push rdx",               // arg3
    "push rsi",               // arg2
    "push rdi",               // arg1
    "push rax",               // num
    "mov rdi, rsp",
    "mov rax, [rip + HUESOS_SYSCALL_HANDLER]",
    "test rax, rax",
    "jz 2f",
    "call rax",
    "2:",
    "pop rax", // num (unused after call but keep stack balanced)
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop r10",
    "pop r8",
    "pop rcx", // user_rip
    "pop r11", // user_rflags
    "pop rsp", // restore user rsp last
    "sysretq",
);
