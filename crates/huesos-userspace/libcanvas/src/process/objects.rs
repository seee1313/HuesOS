//! Safe wrappers for process/thread/VMAR handles.

use crate::channel::Channel;
use crate::handle::Handle;
use crate::port::Port;
use crate::raw;
use crate::vmo::Vmo;
use huesos_abi::{
    HandleValue, ProcessBindExitPortArgs, Syscall, VmarCreateChildArgs, VmarMapArgs, VmarOpArgs,
    BOOTSTRAP_HANDLE, INVALID_HANDLE,
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
        let ret = raw::syscall2(Syscall::ProcessSetAffinity, self.0.raw() as u64, cpu as u64);
        raw::decode(ret)?;
        Ok(())
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

    /// Borrow the underlying thread handle.
    pub fn handle(&self) -> &Handle {
        &self.0
    }
}

impl Vmar {
    /// Wrap a raw VMAR handle returned by the kernel.
    pub(crate) unsafe fn from_raw(raw: HandleValue) -> Self {
        Self(unsafe { Handle::from_raw(raw) })
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
