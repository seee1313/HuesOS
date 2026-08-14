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

mod acpi_broker;
mod callbacks;
mod channel;
mod debug;
mod entropy;
mod framebuffer;
mod handle;
mod job;
mod key;
mod observe;
mod port_interrupt;
mod process;
/// Resource capability primitive syscalls
/// (`ResourceCreate`, `ProcessMarkCritical`). Gated on the root
/// supervisor KOID via [`resource::set_root_supervisor_predicate`].
pub mod resource;
mod signal;
mod system;
/// Recoverable user-memory access primitives with `.ex_table` fault
/// recovery. `pub` because the kernel's `extable_test=1` synthetic
/// probe calls [`user_access::synthetic_recoverable_copy_probe`]
/// directly. Ordinary syscall handlers still route through
/// [`user_memory::copy_from_user`] / [`copy_to_user`][`user_memory::copy_to_user`],
/// which enforce validate_range + user_memory_lock before calling
/// into user_access.
pub mod user_access;
mod user_memory;
mod util;
mod vmo;
mod waitset;

use huesos_abi::{
    ChannelConsumeArgs, ChannelPeekArgs, ChannelReadEtcArgs, ErrorCode, FramebufferBlitArgs,
    FramebufferInfo, HandleValue, JobBindQuotaPortArgs, JobCreateArgs, JobSetLimitsArgs,
    JobSetNameArgs, PortPacket, ProcessBindExitPortArgs, ProcessCreateInJobArgs, ResourceMapArgs,
    VmarCreateChildArgs, VmarMapArgs, VmarOpArgs, WaitSetWaitArgs,
};

pub use callbacks::{
    set_clock_fn, set_cpu_mask_fn, set_current_cpu_fn, set_debug_write_fn, set_exit_fn,
    set_heap_extend_fn, set_process_create_fn, set_process_create_in_job_fn, set_resource_map_fn,
    set_shutdown_fn, set_thread_start_fn, set_vmar_map_fn, set_vmar_protect_fn, set_vmar_unmap_fn,
    set_yield_fn, HeapExtendFn, ProcessCreateFn, ProcessCreateInJobFn, ResourceMapFn,
    ThreadStartFn, VmarMapFn, VmarOpFn,
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
        S::FramebufferBlit => {
            // FramebufferBlit is capability-gated: `a1` is a HandleValue
            // naming a caller-owned `FrameDraw` Resource, `a2` points
            // to the FramebufferBlitArgs. The capability check runs
            // inside `sys_framebuffer_blit` before the pointer is read.
            framebuffer::sys_framebuffer_blit(a1 as HandleValue, a2 as *const FramebufferBlitArgs)
        }
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
        S::PortQueue => port_interrupt::sys_port_queue(a1 as HandleValue, a2 as *const PortPacket),
        S::VolumeKeyGet => key::sys_volume_key_get(a1 as *mut [u8; 32]),
        S::SystemGetEntropy => entropy::sys_system_get_entropy(a1 as *mut u8, a2 as usize),
        S::VmarHeapExtend => entropy::sys_vmar_heap_extend(a1 as *const huesos_abi::HeapExtendArgs),
        S::SystemKnobGet => observe::sys_system_knob_get(a1 as u32, a2 as *mut u64),
        S::SystemKnobSet => {
            observe::sys_system_knob_set(a1 as u32, a2, a3 as *mut u64, a4 as HandleValue)
        }
        S::SystemObservationRead => {
            observe::sys_system_observation_read(a1, a2 as *mut u8, a3 as usize)
        }
        S::InterruptCreate => {
            port_interrupt::sys_interrupt_create(a1 as u32, a2 as *mut HandleValue)
        }
        S::InterruptCreateForResource => port_interrupt::sys_interrupt_create_for_resource(
            a1 as HandleValue,
            a2 as u32,
            a3 as *mut HandleValue,
        ),
        S::InterruptBindPort => {
            port_interrupt::sys_interrupt_bind_port(a1 as HandleValue, a2 as HandleValue, a3)
        }
        S::ProcessWait => process::sys_process_wait(a1 as HandleValue, a2 as *mut i64),
        S::ClockGetMonotonic => system::sys_clock_get_monotonic(),
        S::SystemShutdown => system::sys_system_shutdown(),
        S::ProcessGetExitCode => {
            process::sys_process_get_exit_code(a1 as HandleValue, a2 as *mut i64)
        }
        S::AcpiBrokerCall => acpi_broker::sys_acpi_broker_call(
            a1 as HandleValue,
            a2 as *const huesos_abi::acpi_broker::Request,
            a3 as *mut huesos_abi::acpi_broker::Response,
        ),
        S::VmoCreateEx => vmo::sys_vmo_create_ex(a1 as usize, a2 as u32, a3 as *mut HandleValue),
        S::VmarUnmap => process::sys_vmar_unmap(a1 as *const VmarOpArgs),
        S::VmarProtect => process::sys_vmar_protect(a1 as *const VmarOpArgs),
        S::ChannelPeek => channel::sys_channel_peek(a1 as *const ChannelPeekArgs),
        S::ChannelConsume => channel::sys_channel_consume(a1 as *const ChannelConsumeArgs),
        S::WaitSetWait => waitset::sys_waitset_wait(a1 as *const WaitSetWaitArgs),
        S::ResourceCreate => {
            resource::sys_resource_create(a1 as u32, a2, a3, a4 as u32, a5 as *mut HandleValue)
        }
        S::ResourceMap => resource::sys_resource_map(a1 as *const ResourceMapArgs),
        S::ProcessMarkCritical => resource::sys_process_mark_critical(a1 as HandleValue),
        S::HardHalt => resource::sys_hard_halt(a1 as HandleValue),
        S::IoPortWrite8 => resource::sys_ioport_write8(a1 as HandleValue, a2 as u32, a3 as u32),
        S::IoPortRead8 => resource::sys_ioport_read8(a1 as HandleValue, a2 as u32),
        S::ProcessSetAffinity => process::sys_process_set_affinity(a1 as HandleValue, a2 as usize),
        S::SystemCpuCount => system::sys_system_cpu_count(),
        S::SystemCurrentCpu => system::sys_system_current_cpu(),
        S::ProcessSetAffinityMask => {
            process::sys_process_set_affinity_mask(a1 as HandleValue, a2, a3 as usize)
        }
        S::ProcessGetAffinity => {
            process::sys_process_get_affinity(a1 as HandleValue, a2 as *mut u64, a3 as *mut u64)
        }
        S::VmarCreateChild => process::sys_vmar_create_child(a1 as *const VmarCreateChildArgs),
        S::SignalCreate => signal::sys_signal_create(a1 as *mut HandleValue),
        S::SignalSet => signal::sys_signal_set(a1 as HandleValue),
        S::SignalClear => signal::sys_signal_clear(a1 as HandleValue),
        S::ProcessBindExitPort => {
            process::sys_process_bind_exit_port(a1 as *const ProcessBindExitPortArgs)
        }
        S::ProcessSetSchedulerFlags => {
            process::sys_process_set_scheduler_flags(a1 as HandleValue, a2 as u32)
        }
        S::JobDefault => job::sys_job_default(a1 as *mut HandleValue),
        S::JobCreate => job::sys_job_create(a1 as *const JobCreateArgs),
        S::JobSetLimits => job::sys_job_set_limits(a1 as *const JobSetLimitsArgs),
        S::JobBindQuotaPort => job::sys_job_bind_quota_port(a1 as *const JobBindQuotaPortArgs),
        S::ProcessCreateInJob => {
            process::sys_process_create_in_job(a1 as *const ProcessCreateInJobArgs)
        }
        S::JobSetName => job::sys_job_set_name(a1 as *const JobSetNameArgs),
    }
}
