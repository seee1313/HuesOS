//! Job handles and hierarchical quota controls.

use crate::handle::Handle;
use crate::port::Port;
use crate::raw;
use huesos_abi::{
    HandleValue, JobBindQuotaPortArgs, JobCreateArgs, JobLimitsAbi, JobSetLimitsArgs,
    JobSetNameArgs, ProcessCreateInJobArgs, Syscall, INVALID_HANDLE,
};

use crate::process::{Process, Vmar};

/// A Job owns processes and a quota-tree node.
#[derive(Debug)]
pub struct Job(Handle);

/// Quota limits for Job syscalls. `u64::MAX` means unlimited.
pub type JobLimits = JobLimitsAbi;

impl Job {
    /// Get a handle to the caller's current Job.
    pub fn current() -> crate::Result<Self> {
        let mut out: HandleValue = INVALID_HANDLE;
        let ret = raw::syscall1(Syscall::JobDefault, &mut out as *mut HandleValue as u64);
        raw::decode(ret)?;
        Ok(Self(unsafe { Handle::from_raw(out) }))
    }

    /// Create a child Job.
    pub fn create_child(&self, limits: JobLimits) -> crate::Result<Self> {
        let mut out: HandleValue = INVALID_HANDLE;
        let args = JobCreateArgs {
            parent: self.0.raw(),
            limits,
            out_job: &mut out as *mut HandleValue,
        };
        let ret = raw::syscall1(Syscall::JobCreate, &args as *const _ as u64);
        raw::decode(ret)?;
        Ok(Self(unsafe { Handle::from_raw(out) }))
    }

    /// Replace this Job's limits.
    pub fn set_limits(&self, limits: JobLimits) -> crate::Result<()> {
        let args = JobSetLimitsArgs {
            job: self.0.raw(),
            limits,
        };
        let ret = raw::syscall1(Syscall::JobSetLimits, &args as *const _ as u64);
        raw::decode(ret)?;
        Ok(())
    }

    /// Replace this Job's diagnostic name.
    pub fn set_name(&self, name: &str) -> crate::Result<()> {
        let args = JobSetNameArgs {
            job: self.0.raw(),
            name: name.as_ptr(),
            name_len: name.len() as u64,
        };
        let ret = raw::syscall1(Syscall::JobSetName, &args as *const _ as u64);
        raw::decode(ret)?;
        Ok(())
    }

    /// Bind a Port that receives quota-exhaustion packets.
    pub fn bind_quota_port(&self, port: &Port, key: u64) -> crate::Result<()> {
        let args = JobBindQuotaPortArgs {
            job: self.0.raw(),
            port: port.handle().raw(),
            key,
            flags: 0,
        };
        let ret = raw::syscall1(Syscall::JobBindQuotaPort, &args as *const _ as u64);
        raw::decode(ret)?;
        Ok(())
    }

    /// Create a suspended process owned by this Job.
    pub fn create_process(&self, name: &str) -> crate::Result<(Process, Vmar)> {
        let mut process: HandleValue = INVALID_HANDLE;
        let mut root_vmar: HandleValue = INVALID_HANDLE;
        let args = ProcessCreateInJobArgs {
            job: self.0.raw(),
            name: name.as_ptr(),
            name_len: name.len() as u64,
            out_process: &mut process as *mut HandleValue,
            out_root_vmar: &mut root_vmar as *mut HandleValue,
        };
        let ret = raw::syscall1(Syscall::ProcessCreateInJob, &args as *const _ as u64);
        raw::decode(ret)?;
        Ok((unsafe { Process::from_raw(process) }, unsafe {
            Vmar::from_raw(root_vmar)
        }))
    }

    /// Borrow the underlying handle.
    pub fn handle(&self) -> &Handle {
        &self.0
    }

    /// Consume the wrapper and return the generic handle.
    pub fn into_handle(self) -> Handle {
        self.0
    }
}
