//! x86_64 context switch via raw assembly, plus the ring3 entry trampoline.

use core::arch::global_asm;

/// Saved CPU context for a task.
///
/// Only callee-saved registers plus RIP/RSP/RFLAGS/CR3 are stored. The
/// compiler saves the rest across the `extern "C"` boundary.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Context {
    /// r15
    pub r15: u64,
    /// r14
    pub r14: u64,
    /// r13
    pub r13: u64,
    /// r12
    pub r12: u64,
    /// rbp
    pub rbp: u64,
    /// rbx
    pub rbx: u64,
    /// Stack pointer.
    pub rsp: u64,
    /// RFLAGS.
    pub rflags: u64,
    /// Instruction pointer.
    pub rip: u64,
    /// CR3 (page table root) for this task's address space.
    pub cr3: u64,
}

impl Context {
    /// Create a zeroed context.
    pub const fn zero() -> Self {
        Self {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            rsp: 0,
            rflags: 0,
            rip: 0,
            cr3: 0,
        }
    }

    /// Create a new context that will start executing `entry` with
    /// `stack_top`, in the given address space (`cr3`).
    ///
    /// `stack_top` must be 8-byte aligned and point *just past* the last
    /// valid byte of the stack. We reserve 8 bytes at the top for the
    /// "return" address used when the thread function eventually `ret`s.
    pub fn new(entry: extern "C" fn() -> !, stack_top: *mut u8, cr3: u64) -> Self {
        Self {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            rsp: stack_top as u64,
            rflags: 0x202, // IF = 1
            rip: entry as u64,
            cr3,
        }
    }
}

global_asm!(
    ".global context_switch",
    "context_switch:",
    // Save callee-saved registers.
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    // Save stack pointer (offset 48 in Context).
    "mov [rdi + 48], rsp",
    // Save RFLAGS (offset 56).
    "pushfq",
    "pop rax",
    "mov [rdi + 56], rax",
    // Switch address space if CR3 differs (offset 72).
    "mov rax, [rsi + 72]",
    "mov rcx, cr3",
    "cmp rax, rcx",
    "je 1f",
    "mov cr3, rax",
    "1:",
    // Load new stack pointer.
    "mov rsp, [rsi + 48]",
    // Load new RFLAGS.
    "push qword ptr [rsi + 56]",
    "popfq",
    // Load callee-saved registers.
    "mov r15, [rsi]",
    "mov r14, [rsi + 8]",
    "mov r13, [rsi + 16]",
    "mov r12, [rsi + 24]",
    "mov rbp, [rsi + 32]",
    "mov rbx, [rsi + 40]",
    // Push new RIP and "return" into the new task.
    "push qword ptr [rsi + 64]",
    "ret",
);

unsafe extern "C" {
    /// Switch CPU context from `old` to `new`.
    ///
    /// # Safety
    /// Must be called with interrupts disabled. Both pointers must be valid
    /// for the lifetime of the call.
    pub unsafe fn context_switch(old: *mut Context, new: *const Context);
}

global_asm!(
    ".global enter_userspace",
    "enter_userspace:",
    // Args (SysV): rdi = user_rip, rsi = user_rsp, rdx = user_cs, rcx = user_ss, r8 = user_rflags
    "mov ax, dx",       // user_cs into ax temporarily unused; we build iretq frame directly
    "push rcx",         // SS
    "push rsi",         // RSP
    "push r8",          // RFLAGS
    "push rdx",         // CS
    "push rdi",         // RIP
    "xor rax, rax",
    "xor rbx, rbx",
    "xor rcx, rcx",
    "xor rdx, rdx",
    "xor rsi, rsi",
    "xor rdi, rdi",
    "xor rbp, rbp",
    "xor r8, r8",
    "xor r9, r9",
    "xor r10, r10",
    "xor r11, r11",
    "xor r12, r12",
    "xor r13, r13",
    "xor r14, r14",
    "xor r15, r15",
    "iretq",
);

unsafe extern "C" {
    /// Perform the initial ring0 -> ring3 transition via `iretq`.
    ///
    /// # Safety
    /// `user_rip`/`user_rsp` must point into valid, mapped user memory in
    /// the currently active address space, and `user_cs`/`user_ss` must be
    /// valid ring3 selectors (RPL=3).
    pub unsafe fn enter_userspace(
        user_rip: u64,
        user_rsp: u64,
        user_cs: u64,
        user_ss: u64,
        user_rflags: u64,
    ) -> !;
}
