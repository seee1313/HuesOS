//! # HuesOS Syscall Interface
//!
//! Table-driven syscall dispatch, called from the arch-level `syscall`
//! trampoline with the raw register frame. Syscall numbers and error codes
//! live in `huesos-abi`, the single shared source of truth between this
//! (kernel-side) dispatcher and `libcanvas` (the userspace-side safe
//! wrapper library) — see that crate's docs for why duplicating these
//! constants in two places would be a bug waiting to happen.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

mod callbacks;
mod channel;
mod debug;
mod framebuffer;
mod handle;
mod port_interrupt;
mod process;
mod system;
mod user_memory;
mod util;
mod vmo;

use huesos_abi::{
    ChannelReadEtcArgs, ErrorCode, FramebufferBlitArgs, FramebufferInfo, HandleValue, PortPacket,
    VmarMapArgs,
};

pub use callbacks::{
    set_clock_fn, set_debug_write_fn, set_exit_fn, set_process_create_fn, set_shutdown_fn,
    set_thread_start_fn, set_vmar_map_fn, set_yield_fn, ProcessCreateFn, ThreadStartFn, VmarMapFn,
};

/// Result type for syscalls: `Ok(value)` or a negative error code.
pub type SyscallResult = Result<i64, ErrorCode>;

/// Dispatch a syscall by number. This is architecture-independent; the
/// arch layer is responsible for extracting `num`/`a1..a5` from registers.
///
/// Unknown syscall numbers (including ones from a future ABI version this
/// kernel build predates) return `ErrorCode::NotSupported` rather than
/// silently doing nothing or panicking — callers can detect "this kernel
/// is too old for what I'm asking" as a normal, recoverable condition.
pub fn dispatch(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> SyscallResult {
    use huesos_abi::Syscall as S;
    let Some(syscall) = S::from_raw(num) else {
        return Err(ErrorCode::NotSupported);
    };
    match syscall {
        S::Nop => Ok(0),
        S::VmoCreate => vmo::sys_vmo_create(a1 as usize, a2 as *mut HandleValue),
        S::HandleClose => handle::sys_handle_close(a1 as HandleValue),
        S::HandleDuplicate => {
            handle::sys_handle_duplicate(a1 as HandleValue, a2 as u32, a3 as *mut HandleValue)
        }
        S::Yield => process::sys_yield(),
        S::VmoRead => vmo::sys_vmo_read(a1 as HandleValue, a2, a3 as *mut u8, a4 as usize),
        S::VmoWrite => vmo::sys_vmo_write(a1 as HandleValue, a2, a3 as *const u8, a4 as usize),
        S::ChannelCreate => {
            channel::sys_channel_create(a1 as *mut HandleValue, a2 as *mut HandleValue)
        }
        S::ChannelWrite => channel::sys_channel_write(
            a1 as HandleValue,
            a2 as *const u8,
            a3 as u32,
            a4 as *const HandleValue,
            a5 as u32,
        ),
        S::ChannelRead => channel::sys_channel_read(
            a1 as HandleValue,
            a2 as *mut u8,
            a3 as u32,
            a4 as *mut u32,
            a5,
        ),
        S::ChannelReadEtc => channel::sys_channel_read_etc(a1 as *const ChannelReadEtcArgs, a2),
        S::ProcessExit => process::sys_process_exit(a1 as i64),
        S::DebugWrite => debug::sys_debug_write(a1 as *const u8, a2 as usize),
        S::FramebufferInfo => framebuffer::sys_framebuffer_info(a1 as *mut FramebufferInfo),
        S::FramebufferBlit => framebuffer::sys_framebuffer_blit(a1 as *const FramebufferBlitArgs),
        S::ProcessCreate => process::sys_process_create(
            a1 as *const u8,
            a2 as usize,
            a3 as *mut HandleValue,
            a4 as *mut HandleValue,
        ),
        S::ThreadCreate => process::sys_thread_create(
            a1 as HandleValue,
            a2 as *const u8,
            a3 as usize,
            a4 as *mut HandleValue,
        ),
        S::ThreadStart => {
            process::sys_thread_start(a1 as HandleValue, a2, a3, a4 as *mut HandleValue)
        }
        S::VmarMap => process::sys_vmar_map(a1 as *const VmarMapArgs),
        S::PortCreate => port_interrupt::sys_port_create(a1 as *mut HandleValue),
        S::PortRead => port_interrupt::sys_port_read(a1 as HandleValue, a2 as *mut PortPacket, a3),
        S::InterruptCreate => {
            port_interrupt::sys_interrupt_create(a1 as u32, a2 as *mut HandleValue)
        }
        S::InterruptBindPort => {
            port_interrupt::sys_interrupt_bind_port(a1 as HandleValue, a2 as HandleValue, a3)
        }
        S::ProcessWait => process::sys_process_wait(a1 as HandleValue, a2 as *mut i64),
        S::ClockGetMonotonic => system::sys_clock_get_monotonic(),
        S::SystemShutdown => system::sys_system_shutdown(),
        S::ProcessGetExitCode => {
            process::sys_process_get_exit_code(a1 as HandleValue, a2 as *mut i64)
        }
    }
}
