//! Process/thread-level primitives: exiting, yielding, and the skeleton
//! Zircon-like process launch wrappers.

use crate::channel::Channel;
use crate::handle::Handle;
use crate::raw;
use crate::vmo::Vmo;
use huesos_abi::{HandleValue, Syscall, VmarMapArgs, BOOTSTRAP_HANDLE, INVALID_HANDLE};

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
        let ret = unsafe {
            raw::syscall4(
                Syscall::ProcessCreate,
                name.as_ptr() as u64,
                name.len() as u64,
                &mut process as *mut HandleValue as u64,
                &mut root_vmar as *mut HandleValue as u64,
            )
        };
        raw::decode(ret)?;
        Ok((
            Self(unsafe { Handle::from_raw(process) }),
            Vmar(unsafe { Handle::from_raw(root_vmar) }),
        ))
    }

    /// Query the process exit code.
    ///
    /// Returns `Ok(None)` while the process is still running. A future
    /// blocking implementation can keep this wrapper and change only the
    /// kernel side once ports/waits are available.
    pub fn wait_exit(&self) -> crate::Result<Option<i64>> {
        let mut code: i64 = 0;
        let ret = unsafe {
            raw::syscall2(
                Syscall::ProcessWait,
                self.0.raw() as u64,
                &mut code as *mut i64 as u64,
            )
        };
        match raw::decode(ret) {
            Ok(_) => Ok(Some(code)),
            Err(crate::ErrorCode::ShouldWait) => Ok(None),
            Err(e) => Err(e),
        }
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
        let ret = unsafe {
            raw::syscall4(
                Syscall::ThreadCreate,
                process.handle().raw() as u64,
                name.as_ptr() as u64,
                name.len() as u64,
                &mut thread as *mut HandleValue as u64,
            )
        };
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
        let ret = unsafe {
            raw::syscall4(
                Syscall::ThreadStart,
                self.0.raw() as u64,
                entry,
                stack,
                &mut parent_bootstrap as *mut HandleValue as u64,
            )
        };
        raw::decode(ret)?;
        Ok(unsafe { Channel::from_raw(parent_bootstrap) })
    }

    /// Borrow the underlying thread handle.
    pub fn handle(&self) -> &Handle {
        &self.0
    }
}

impl Vmar {
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
        let ret = unsafe { raw::syscall1(Syscall::VmarMap, &args as *const _ as u64) };
        raw::decode(ret).map(|mapped| mapped as u64)
    }

    /// Borrow the underlying VMAR handle.
    pub fn handle(&self) -> &Handle {
        &self.0
    }
}

/// Exit the current process with `code`. Never returns.
pub fn exit(code: i64) -> ! {
    unsafe {
        let _ = raw::syscall1(Syscall::ProcessExit, code as u64);
    }
    // The kernel's ProcessExit handler never returns control, but the
    // compiler doesn't know that about a syscall; park just in case.
    loop {
        core::hint::spin_loop();
    }
}

/// Yield the remainder of the current thread's scheduling quantum
/// cooperatively.
pub fn yield_now() {
    unsafe {
        let _ = raw::syscall0(Syscall::Yield);
    }
}
