//! Job and quota syscalls.

use alloc::sync::Arc;
use huesos_abi::{
    ErrorCode, HandleValue, JobBindQuotaPortArgs, JobCreateArgs, JobLimitsAbi, JobSetLimitsArgs,
};
use huesos_object::{Handle, KernelObjectExt, Rights};
use huesos_quota::Limits;

use crate::{user_memory, util::current_proc, SyscallResult};

fn limits_from_abi(limits: JobLimitsAbi) -> Limits {
    Limits {
        max_memory: limits.max_memory,
        max_handles: limits.max_handles,
        max_cpu_ticks: limits.max_cpu_ticks,
    }
}

/// Return a handle to the caller's current Job.
pub(crate) fn sys_job_default(out: *mut HandleValue) -> SyscallResult {
    user_memory::validate_write(out)?;
    let proc = current_proc()?;
    let job = proc.job();
    proc.handles
        .add_with_commit(
            Handle::new(
                job.koid(),
                Rights::READ | Rights::GET_PROPERTY | Rights::DUPLICATE | Rights::TRANSFER,
            ),
            |handle| user_memory::write_value(out, &handle),
        )
        .map(|_| 0)
}

/// Create a child Job.
pub(crate) fn sys_job_create(args_ptr: *const JobCreateArgs) -> SyscallResult {
    let args = user_memory::read_value(args_ptr)?;
    user_memory::validate_write(args.out_job)?;
    let proc = current_proc()?;
    let parent_handle = proc.handles.get(args.parent).ok_or(ErrorCode::BadHandle)?;
    if !parent_handle.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let parent_obj =
        huesos_object::lookup_object(parent_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let parent = parent_obj
        .downcast_arc::<huesos_object::Job>()
        .map_err(|_| ErrorCode::WrongType)?;
    let child = huesos_object::Job::child(&parent, "job", limits_from_abi(args.limits))
        .map_err(|_| ErrorCode::InvalidArgs)?;
    let koid = child.koid();
    huesos_object::register_object(child);
    match proc.handles.add_with_commit(
        Handle::new(koid, Rights::DEFAULT | Rights::SET_PROPERTY),
        |handle| user_memory::write_value(args.out_job, &handle),
    ) {
        Ok((handle, _)) => Ok(handle as i64),
        Err(error) => {
            if let Some(object) = huesos_object::lookup_object(koid) {
                if let Some(job) = object.downcast_ref::<huesos_object::Job>() {
                    let _ = job.rollback_unpublished_quota_node();
                }
            }
            huesos_object::unregister_object(koid);
            Err(error)
        }
    }
}

/// Replace Job limits.
pub(crate) fn sys_job_set_limits(args_ptr: *const JobSetLimitsArgs) -> SyscallResult {
    let args = user_memory::read_value(args_ptr)?;
    let proc = current_proc()?;
    let job_handle = proc.handles.get(args.job).ok_or(ErrorCode::BadHandle)?;
    if !job_handle.has_rights(Rights::SET_PROPERTY) {
        return Err(ErrorCode::AccessDenied);
    }
    let job_obj = huesos_object::lookup_object(job_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let job = job_obj
        .downcast_ref::<huesos_object::Job>()
        .ok_or(ErrorCode::WrongType)?;
    if job.set_limits(limits_from_abi(args.limits)) {
        Ok(0)
    } else {
        Err(ErrorCode::InvalidArgs)
    }
}

/// Bind a Port for quota-exhaustion packets.
pub(crate) fn sys_job_bind_quota_port(args_ptr: *const JobBindQuotaPortArgs) -> SyscallResult {
    let args = user_memory::read_value(args_ptr)?;
    if args.flags != 0 {
        return Err(ErrorCode::InvalidArgs);
    }
    let proc = current_proc()?;
    let job_handle = proc.handles.get(args.job).ok_or(ErrorCode::BadHandle)?;
    if !job_handle.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let port_handle = proc.handles.get(args.port).ok_or(ErrorCode::BadHandle)?;
    if !port_handle.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let job_obj = huesos_object::lookup_object(job_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let job = job_obj
        .downcast_ref::<huesos_object::Job>()
        .ok_or(ErrorCode::WrongType)?;
    let port_obj = huesos_object::lookup_object(port_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let port: Arc<huesos_object::Port> = port_obj
        .downcast_arc::<huesos_object::Port>()
        .map_err(|_| ErrorCode::WrongType)?;
    if job.bind_quota_port(port, args.key) {
        Ok(0)
    } else {
        Err(ErrorCode::Busy)
    }
}
