//! Safe wrappers for process/thread/VMAR handles.

use crate::channel::Channel;
use crate::handle::Handle;
use crate::port::Port;
use crate::raw;
use crate::vmo::Vmo;
use huesos_abi::{
    CpuMask256, HandleValue, ProcessBindExitPortArgs, ProcessGetAffinityMask256Args,
    ProcessSetAffinityMask256Args, Syscall, ThreadStartArgs, VmarCreateChildArgs, VmarMapArgs,
    VmarOpArgs, BOOTSTRAP_HANDLE, INVALID_HANDLE,
};

/// Initial bootstrap channel handle number installed in a newly-started
/// child process by `Thread::start`.
pub const CHILD_BOOTSTRAP_HANDLE: HandleValue = BOOTSTRAP_HANDLE;

/// An owned process handle.
#[derive(Debug)]
pub struct Process(Handle);

/// An owned thread handle.
#[derive(Debug)]
pub struct Thread(Handle);

/// An owned VMAR handle.
#[derive(Debug)]
pub struct Vmar(Handle);

impl Process {
    /// Wrap a raw process handle returned by the kernel.
    pub(crate) unsafe fn from_raw(raw: HandleValue) -> Self {
        Self(unsafe { Handle::from_raw(raw) })
    }

    /// Create a suspended process and its root VMAR.
    ///
    /// This is an ABI skeleton: current kernels will return
    /// `ErrorCode::NotSupported` until the kernel-side implementation lands.
    pub fn create(name: &str) -> crate::Result<(Self, Vmar)> {
        if name.is_empty() {
            return Err(crate::ErrorCode::InvalidArgs);
        }

        let mut process: HandleValue = INVALID_HANDLE;
        let mut root_vmar: HandleValue = INVALID_HANDLE;
        let ret = raw::syscall4(
            Syscall::ProcessCreate,
            name.as_ptr() as u64,
            name.len() as u64,
            &mut process as *mut HandleValue as u64,
            &mut root_vmar as *mut HandleValue as u64,
        );
        raw::decode(ret)?;
        Ok((
            Self(unsafe { Handle::from_raw(process) }),
            Vmar(unsafe { Handle::from_raw(root_vmar) }),
        ))
    }

    /// Block until the process exits and return its exit code.
    pub fn wait_exit(&self) -> crate::Result<i64> {
        let mut code: i64 = 0;
        let ret = raw::syscall2(
            Syscall::ProcessWait,
            self.0.raw() as u64,
            &mut code as *mut i64 as u64,
        );
        raw::decode(ret)?;
        Ok(code)
    }

    /// Non-blocking exit probe: `Ok(code)` once the process has exited,
    /// `Err(ShouldWait)` while it is still running.
    pub fn exit_code(&self) -> crate::Result<i64> {
        let mut code: i64 = 0;
        let ret = raw::syscall2(
            Syscall::ProcessGetExitCode,
            self.0.raw() as u64,
            &mut code as *mut i64 as u64,
        );
        raw::decode(ret)?;
        Ok(code)
    }

    /// Terminate this process with `code` (`ProcessTerminate`).
    ///
    /// Requires a `Process` handle with `WRITE` rights, which is what
    /// `ProcessCreate`/`spawn_*` hand to the parent. Every thread of the
    /// target is stopped, `ProcessWait` observers wake with `code`, and the
    /// target's resources are released through the normal teardown path — the
    /// same observable outcome as the process exiting on its own. Idempotent:
    /// terminating an already-exited process succeeds and keeps the first
    /// exit status.
    pub fn terminate(&self, code: i64) -> crate::Result<()> {
        let ret = raw::syscall2(Syscall::ProcessTerminate, self.0.raw() as u64, code as u64);
        raw::decode(ret).map(|_| ())
    }

    /// Record the execution personality (`ELF64` or `PE64`) of this process.
    pub fn set_abi(&self, abi: huesos_abi::ProcessAbi) -> crate::Result<()> {
        let ret = raw::syscall2(Syscall::ProcessSetAbi, self.0.raw() as u64, abi as u64);
        raw::decode(ret).map(|_| ())
    }

    /// Record the execution personality (`ELF64` or `PE64`) of the calling process.
    pub fn set_current_abi(abi: huesos_abi::ProcessAbi) -> crate::Result<()> {
        let ret = raw::syscall2(Syscall::ProcessSetAbi, 0, abi as u64);
        raw::decode(ret).map(|_| ())
    }

    /// Queue a process-exit packet to `port` when this process exits.
    pub fn bind_exit_port(&self, port: &Port, key: u64) -> crate::Result<()> {
        let args = ProcessBindExitPortArgs {
            process: self.0.raw(),
            port: port.handle().raw(),
            key,
            flags: 0,
        };
        let ret = raw::syscall1(Syscall::ProcessBindExitPort, &args as *const _ as u64);
        raw::decode(ret)?;
        Ok(())
    }

    /// Query process completion without blocking.
    pub fn poll_exit(&self) -> crate::Result<Option<i64>> {
        let mut code = 0i64;
        let ret = raw::syscall2(
            Syscall::ProcessGetExitCode,
            self.0.raw() as u64,
            &mut code as *mut i64 as u64,
        );
        match raw::decode(ret) {
            Ok(_) => Ok(Some(code)),
            Err(crate::ErrorCode::ShouldWait) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Set the process's single-CPU affinity before its initial thread starts.
    pub fn set_affinity(&self, cpu: usize) -> crate::Result<()> {
        let mask = CpuMask256::one(cpu).ok_or(crate::ErrorCode::InvalidArgs)?;
        self.set_affinity_mask_256(mask, cpu)
    }

    /// Set the complete 256-CPU affinity mask before the initial thread starts.
    /// The selected home CPU must be present in `mask` and online.
    pub fn set_affinity_mask_256(&self, mask: CpuMask256, home_cpu: usize) -> crate::Result<()> {
        let args = ProcessSetAffinityMask256Args {
            process: self.0.raw(),
            home_cpu: u32::try_from(home_cpu).map_err(|_| crate::ErrorCode::InvalidArgs)?,
            flags: 0,
            mask,
        };
        let ret = raw::syscall1(
            Syscall::ProcessSetAffinityMask256,
            &args as *const ProcessSetAffinityMask256Args as u64,
        );
        raw::decode(ret).map(|_| ())
    }

    /// Read the complete 256-CPU affinity mask and home CPU.
    pub fn affinity_mask_256(&self) -> crate::Result<(CpuMask256, usize)> {
        let mut mask = CpuMask256::empty();
        let mut home_cpu = 0u32;
        let args = ProcessGetAffinityMask256Args {
            process: self.0.raw(),
            reserved: 0,
            out_mask: &mut mask,
            out_home_cpu: &mut home_cpu,
        };
        let ret = raw::syscall1(
            Syscall::ProcessGetAffinityMask256,
            &args as *const ProcessGetAffinityMask256Args as u64,
        );
        raw::decode(ret)?;
        Ok((mask, home_cpu as usize))
    }

    /// Set the process's CPU affinity mask and home CPU before its initial
    /// thread starts.
    pub fn set_affinity_mask(&self, mask: u64, home_cpu: usize) -> crate::Result<()> {
        let ret = raw::syscall3(
            Syscall::ProcessSetAffinityMask,
            self.0.raw() as u64,
            mask,
            home_cpu as u64,
        );
        raw::decode(ret)?;
        Ok(())
    }

    /// Set scheduler flags before the initial thread starts.
    pub fn set_scheduler_flags(&self, flags: u32) -> crate::Result<()> {
        let ret = raw::syscall2(
            Syscall::ProcessSetSchedulerFlags,
            self.0.raw() as u64,
            flags as u64,
        );
        raw::decode(ret)?;
        Ok(())
    }

    /// Query the process's affinity mask and home CPU.
    pub fn affinity(&self) -> crate::Result<(u64, usize)> {
        let mut mask = 0u64;
        let mut home = 0u64;
        let ret = raw::syscall3(
            Syscall::ProcessGetAffinity,
            self.0.raw() as u64,
            &mut mask as *mut u64 as u64,
            &mut home as *mut u64 as u64,
        );
        raw::decode(ret)?;
        Ok((mask, home as usize))
    }

    /// Return an owned handle to the calling process (`Syscall::ProcessSelf`).
    pub fn current() -> crate::Result<Self> {
        let mut handle: HandleValue = INVALID_HANDLE;
        let ret = raw::syscall1(Syscall::ProcessSelf, &mut handle as *mut HandleValue as u64);
        raw::decode(ret)?;
        // SAFETY: the kernel just installed an owned process handle in `handle`.
        Ok(Self(unsafe { Handle::from_raw(handle) }))
    }

    /// The process's stable kernel object ID. This is printable identity, not
    /// authority; operations still require this capability handle and rights.
    pub fn koid(&self) -> crate::Result<u64> {
        self.0.koid()
    }

    /// Borrow the underlying process handle.
    pub fn handle(&self) -> &Handle {
        &self.0
    }
}

impl Thread {
    /// Create a suspended thread inside `process`.
    ///
    /// This reserves the userspace-facing wrapper for the approved
    /// create/map/thread/start launch path; the current kernel returns
    /// `ErrorCode::NotSupported` until implementation commits land.
    pub fn create(process: &Process, name: &str) -> crate::Result<Self> {
        if name.is_empty() {
            return Err(crate::ErrorCode::InvalidArgs);
        }

        let mut thread: HandleValue = INVALID_HANDLE;
        let ret = raw::syscall4(
            Syscall::ThreadCreate,
            process.handle().raw() as u64,
            name.as_ptr() as u64,
            name.len() as u64,
            &mut thread as *mut HandleValue as u64,
        );
        raw::decode(ret)?;
        Ok(Self(unsafe { Handle::from_raw(thread) }))
    }

    /// Start the thread at `entry` with stack pointer `stack`.
    ///
    /// The kernel creates a bootstrap channel pair, installs the child side
    /// as `CHILD_BOOTSTRAP_HANDLE` in the child process, and returns the
    /// parent endpoint to the caller.
    pub fn start(&self, entry: u64, stack: u64) -> crate::Result<Channel> {
        let mut parent_bootstrap: HandleValue = INVALID_HANDLE;
        let ret = raw::syscall4(
            Syscall::ThreadStart,
            self.0.raw() as u64,
            entry,
            stack,
            &mut parent_bootstrap as *mut HandleValue as u64,
        );
        raw::decode(ret)?;
        Ok(unsafe { Channel::from_raw(parent_bootstrap) })
    }

    /// Start a secondary intra-process thread with initial `entry`, `stack`,
    /// `arg0` (`rdi`), and `fs_base` (`MSR_FS_BASE`), without creating a new
    /// bootstrap channel.
    pub fn start_ex(&self, entry: u64, stack: u64, arg0: u64, fs_base: u64) -> crate::Result<u64> {
        let args = ThreadStartArgs {
            thread: self.0.raw(),
            flags: 0,
            entry,
            stack,
            arg0,
            fs_base,
        };
        let ret = raw::syscall1(
            Syscall::ThreadStartEx,
            &args as *const ThreadStartArgs as u64,
        );
        raw::decode(ret).map(|tid| tid as u64)
    }

    /// Block until this thread exits and return its exit code.
    pub fn wait(&self) -> crate::Result<i64> {
        let mut code: i64 = 0;
        let ret = raw::syscall2(
            Syscall::ThreadWait,
            self.0.raw() as u64,
            &mut code as *mut i64 as u64,
        );
        raw::decode(ret)?;
        Ok(code)
    }

    /// Borrow the underlying thread handle.
    pub fn handle(&self) -> &Handle {
        &self.0
    }

    /// Set the calling thread's Ring-3 `GS_BASE` (e.g. Win64 `TEB` linear address).
    pub fn set_current_gs_base(gs_base: u64) -> crate::Result<()> {
        let ret = raw::syscall1(Syscall::ThreadSetGsBase, gs_base);
        raw::decode(ret).map(|_| ())
    }

    /// Read the calling thread's Ring-3 `GS_BASE`.
    pub fn get_current_gs_base() -> crate::Result<u64> {
        let mut out = 0u64;
        let ret = raw::syscall1(Syscall::ThreadGetGsBase, &mut out as *mut u64 as u64);
        raw::decode(ret)?;
        Ok(out)
    }
}

impl Vmar {
    /// Wrap a raw VMAR handle returned by the kernel.
    pub(crate) unsafe fn from_raw(raw: HandleValue) -> Self {
        Self(unsafe { Handle::from_raw(raw) })
    }

    /// Build a VMAR wrapper from an owned generic handle received over IPC.
    pub fn from_handle(handle: Handle) -> Self {
        Self(handle)
    }

    /// Consume this VMAR and return its owned generic handle.
    pub fn into_handle(self) -> Handle {
        self.0
    }

    /// Reserve a child VMAR range inside this VMAR.
    pub fn create_child(&self, addr: u64, len: u64) -> crate::Result<Vmar> {
        let mut child: HandleValue = INVALID_HANDLE;
        let args = VmarCreateChildArgs {
            parent: self.0.raw(),
            addr,
            len,
            flags: 0,
            out_child: &mut child as *mut HandleValue,
        };
        let ret = raw::syscall1(Syscall::VmarCreateChild, &args as *const _ as u64);
        raw::decode(ret)?;
        Ok(Vmar(unsafe { Handle::from_raw(child) }))
    }

    /// Map `vmo` into this VMAR.
    ///
    /// `flags` is a bitmask from [`huesos_abi::vmar_flags`].
    pub fn map(
        &self,
        vmo: &Vmo,
        vmo_offset: u64,
        addr: u64,
        len: u64,
        flags: u32,
    ) -> crate::Result<u64> {
        let args = VmarMapArgs {
            vmar: self.0.raw(),
            vmo: vmo.handle().raw(),
            vmo_offset,
            addr,
            len,
            flags,
        };
        let ret = raw::syscall1(Syscall::VmarMap, &args as *const _ as u64);
        raw::decode(ret).map(|mapped| mapped as u64)
    }

    /// Remove a page-aligned mapping range from this VMAR. Subranges split the
    /// original mapping metadata.
    pub fn unmap(&self, addr: u64, len: u64) -> crate::Result<u64> {
        let args = VmarOpArgs {
            vmar: self.0.raw(),
            addr,
            len,
            flags: 0,
        };
        let ret = raw::syscall1(Syscall::VmarUnmap, &args as *const _ as u64);
        raw::decode(ret).map(|mapped| mapped as u64)
    }

    /// Change permissions on a page-aligned mapping range. Subranges split the
    /// original mapping metadata.
    pub fn protect(&self, addr: u64, len: u64, flags: u32) -> crate::Result<u64> {
        let args = VmarOpArgs {
            vmar: self.0.raw(),
            addr,
            len,
            flags,
        };
        let ret = raw::syscall1(Syscall::VmarProtect, &args as *const _ as u64);
        raw::decode(ret).map(|mapped| mapped as u64)
    }

    /// Borrow the underlying VMAR handle.
    pub fn handle(&self) -> &Handle {
        &self.0
    }
}
