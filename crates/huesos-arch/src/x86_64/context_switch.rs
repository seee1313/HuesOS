//! x86_64 context switch via raw assembly, plus the ring3 entry trampoline.
//!
//! ## A note on the switching scheme (and a bug that used to live here)
//!
//! This uses the classic, fully symmetric stack-based "swtch" pattern (the
//! same one used by xv6, early Linux `switch_to`, etc): callee-saved
//! registers and the return address are *pushed onto the current stack* on
//! save, `rsp` is the only thing recorded in the `Context` struct besides
//! `cr3`, and resuming a task is just: load its saved `rsp`, then `pop`
//! everything back in reverse order, then a plain `ret` — which naturally
//! jumps to whatever return address was sitting on that stack.
//!
//! An earlier version of this code recorded `rip`/`r15..rbx` as separate
//! fields in `Context` and had the *save* half `push` them onto the stack
//! while the *restore* half read them back via `mov` from the `Context`
//! struct fields instead of `pop`-ing them from the stack. Those struct
//! fields were only ever written once, at task creation — never updated by
//! a save — so this "worked" only for a task's very first activation
//! (where `Context::new` had populated them by hand) and silently broke on
//! any *second* resume of the same task, jumping to a stale/zeroed `rip`
//! instead of wherever the task actually was. This is exactly the kind of
//! bug that hides for a while: a single ring3 process that runs to
//! completion within one scheduling quantum never triggers it, but the
//! very next task switch — e.g. resuming the idle task after that process
//! exits — does, and it looked like a `RIP=0` page fault / triple fault at
//! runtime with no compile-time symptom at all.

use core::arch::global_asm;

/// Saved CPU context for a task.
///
/// Only the stack pointer and CR3 are stored here; every other register
/// (callee-saved regs, RFLAGS, the resume address) lives on the task's own
/// stack, exactly where `context_switch`'s save half pushed it — see the
/// module-level docs above for why that matters.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Context {
    /// Stack pointer, pointing at the top of a saved register frame
    /// produced by `context_switch` (or synthesized by [`Context::new`]).
    pub rsp: u64,
    /// CR3 (page table root) for this task's address space.
    pub cr3: u64,
}

impl Context {
    /// Create a zeroed/invalid context. Not safe to switch into directly —
    /// only useful as a placeholder `old` destination when you don't care
    /// about the previously-running context (there isn't one).
    pub const fn zero() -> Self {
        Self { rsp: 0, cr3: 0 }
    }

    /// Create a zeroed context with a specific `cr3`. Still not safe to
    /// switch into as `new` (rsp is 0) — see [`Context::zero`].
    pub const fn zero_with_cr3(cr3: u64) -> Self {
        Self { rsp: 0, cr3 }
    }

    /// Create a new context that will start executing `entry` with
    /// `stack_top`, in the given address space (`cr3`), the first time it
    /// is switched into.
    ///
    /// `stack_top` must be 16-byte aligned and point *just past* the last
    /// valid byte of the stack; at least `FRAME_SIZE` bytes below it must
    /// be valid, writable memory (this function writes a synthetic saved
    /// register frame there matching exactly what `context_switch`'s save
    /// half would have produced, so that resuming a brand new task goes
    /// through the exact same code path as resuming one that has actually
    /// run before).
    pub fn new(entry: extern "C" fn() -> !, stack_top: *mut u8, cr3: u64) -> Self {
        // Layout, from `stack_top` growing down (must match the push order
        // in `context_switch`'s save half, and be unwound in the exact
        // reverse order by its restore half):
        //   [stack_top - 8]  = return address (entry point)
        //   [stack_top - 16] = rbp
        //   [stack_top - 24] = rbx
        //   [stack_top - 32] = r12
        //   [stack_top - 40] = r13
        //   [stack_top - 48] = r14
        //   [stack_top - 56] = r15
        //   [stack_top - 64] = rflags
        // rsp after "restore" finishes popping everything will point at
        // the return address, and `ret` will jump to `entry`.
        const FRAME_SIZE: usize = 64;
        unsafe {
            let frame = stack_top.sub(FRAME_SIZE) as *mut u64;
            frame.add(7).write(entry as *const () as u64); // return addr
            frame.add(6).write(0); // rbp
            frame.add(5).write(0); // rbx
            frame.add(4).write(0); // r12
            frame.add(3).write(0); // r13
            frame.add(2).write(0); // r14
            frame.add(1).write(0); // r15
            frame.add(0).write(0x202); // rflags, IF = 1
        }
        Self {
            rsp: stack_top as u64 - FRAME_SIZE as u64,
            cr3,
        }
    }
}

global_asm!(
    ".global context_switch",
    "context_switch:",
    // ---- Save the outgoing task's state onto its own current stack. ----
    "pushfq",
    "push rbp",
    "push rbx",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    // Persist where that frame now lives (Context.rsp, offset 0) ...
    "mov [rdi + 0], rsp",
    // ... and the *actual currently active* CR3 (Context.cr3, offset 8).
    // This must be read from the CPU, not assumed from the struct: a task
    // that has never been "old" in a save before (e.g. the idle task,
    // which starts out as `current` with a placeholder zeroed context)
    // only gets a correct, valid cr3 recorded here, the first time it's
    // ever switched away from — self-healing before it can matter.
    "mov rax, cr3",
    "mov [rdi + 8], rax",
    // ---- Switch address space if the incoming task needs a different one. ----
    "mov rax, [rsi + 8]",
    "cmp rax, [rdi + 8]",
    "je 1f",
    "mov cr3, rax",
    "1:",
    // ---- Restore the incoming task's state from its own saved stack. ----
    "mov rsp, [rsi + 0]",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbx",
    "pop rbp",
    "popfq",
    // Whatever is left on the stack now is the return address that was
    // saved (or synthesized by `Context::new`) — jump to it.
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
