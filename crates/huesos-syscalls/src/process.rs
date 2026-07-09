//! Process/thread/VMAR launch syscalls plus yield/exit.

use huesos_abi::{ErrorCode, HandleValue, VmarMapArgs, BOOTSTRAP_HANDLE};
use huesos_object::{Handle, KernelObject, KernelObjectExt, Rights};

use crate::{
    callbacks::{EXIT_FN, PROCESS_CREATE_FN, THREAD_START_FN, VMAR_MAP_FN, YIELD_FN},
    util::current_proc,
    SyscallResult,
};

pub(crate) fn sys_yield() -> SyscallResult {
    // Copy the callback out before calling it. `yield_now` context-switches
    // away and does not return until this task is scheduled again; holding a
    // spinlock across that switch deadlocks the next task that tries to yield.
    let yield_fn = *YIELD_FN.lock();
    if let Some(f) = yield_fn {
        f();
    }
    Ok(0)
}

const MAX_PROCESS_NAME_LEN: usize = 64;

pub(crate) fn sys_process_create(
    name_ptr: *const u8,
    name_len: usize,
    out_process: *mut HandleValue,
    out_root_vmar: *mut HandleValue,
) -> SyscallResult {
    if out_process.is_null() || out_root_vmar.is_null() || name_len > MAX_PROCESS_NAME_LEN {
        return Err(ErrorCode::InvalidArgs);
    }
    if name_len > 0 && name_ptr.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }

    let name = if name_len == 0 {
        "process"
    } else {
        let bytes = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
        core::str::from_utf8(bytes).map_err(|_| ErrorCode::InvalidArgs)?
    };

    let create = (*PROCESS_CREATE_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    let (process, root_vmar) = create(name)?;

    let caller = current_proc()?;
    let process_handle = caller
        .handles
        .add(Handle::new(process.koid(), Rights::DEFAULT));
    let root_vmar_handle = caller
        .handles
        .add(Handle::new(root_vmar.koid(), Rights::DEFAULT));

    unsafe {
        *out_process = process_handle;
        *out_root_vmar = root_vmar_handle;
    }
    Ok(0)
}

pub(crate) fn sys_thread_create(
    process_handle: HandleValue,
    name_ptr: *const u8,
    name_len: usize,
    out_thread: *mut HandleValue,
) -> SyscallResult {
    if out_thread.is_null() || name_len > MAX_PROCESS_NAME_LEN {
        return Err(ErrorCode::InvalidArgs);
    }
    if name_len > 0 && name_ptr.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }

    let name = if name_len == 0 {
        "thread"
    } else {
        let bytes = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
        core::str::from_utf8(bytes).map_err(|_| ErrorCode::InvalidArgs)?
    };

    let caller = current_proc()?;
    let process_h = caller
        .handles
        .get(process_handle)
        .ok_or(ErrorCode::BadHandle)?;
    if !process_h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }

    let process_obj = huesos_object::lookup_object(process_h.koid).ok_or(ErrorCode::BadHandle)?;
    let process = process_obj
        .downcast_ref::<huesos_object::Process>()
        .ok_or(ErrorCode::WrongType)?;

    let thread = huesos_object::Thread::new_for_process(name, process.koid());
    let thread_koid = thread.koid();
    huesos_object::register_object(thread);
    let thread_handle = caller
        .handles
        .add(Handle::new(thread_koid, Rights::DEFAULT));

    unsafe {
        *out_thread = thread_handle;
    }
    Ok(0)
}

pub(crate) fn sys_thread_start(
    thread_handle: HandleValue,
    entry: u64,
    stack: u64,
    out_parent_bootstrap: *mut HandleValue,
) -> SyscallResult {
    if entry < huesos_abi::USER_ASPACE_BASE
        || entry >= huesos_abi::USER_ASPACE_END
        || stack < huesos_abi::USER_ASPACE_BASE
        || stack >= huesos_abi::USER_ASPACE_END
        || out_parent_bootstrap.is_null()
    {
        return Err(ErrorCode::InvalidArgs);
    }

    let caller = current_proc()?;
    let thread_h = caller
        .handles
        .get(thread_handle)
        .ok_or(ErrorCode::BadHandle)?;
    if !thread_h.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }

    let thread_obj = huesos_object::lookup_object(thread_h.koid).ok_or(ErrorCode::BadHandle)?;
    let thread = thread_obj
        .downcast_ref::<huesos_object::Thread>()
        .ok_or(ErrorCode::WrongType)?;

    if thread.task_id.lock().is_some() {
        return Err(ErrorCode::Busy);
    }

    let child_process =
        huesos_object::lookup_process(thread.process()).ok_or(ErrorCode::BadHandle)?;

    let (parent_bootstrap, child_bootstrap) = huesos_object::Channel::pair();
    let parent_koid = parent_bootstrap.koid();
    let child_koid = child_bootstrap.koid();
    huesos_object::register_object(parent_bootstrap);
    huesos_object::register_object(child_bootstrap);

    child_process
        .handles
        .insert_at(BOOTSTRAP_HANDLE, Handle::new(child_koid, Rights::DEFAULT))
        .map_err(|_| ErrorCode::Busy)?;

    let start = (*THREAD_START_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    let task_id = start(thread, entry, stack)?;

    let parent_handle = caller
        .handles
        .add(Handle::new(parent_koid, Rights::DEFAULT));
    unsafe {
        *out_parent_bootstrap = parent_handle;
    }
    Ok(task_id as i64)
}

pub(crate) fn sys_vmar_map(args_ptr: *const VmarMapArgs) -> SyscallResult {
    if args_ptr.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }
    let args = unsafe { core::ptr::read_unaligned(args_ptr) };

    let proc = current_proc()?;
    let vmar_handle = proc.handles.get(args.vmar).ok_or(ErrorCode::BadHandle)?;
    if !vmar_handle.has_rights(Rights::WRITE) {
        return Err(ErrorCode::AccessDenied);
    }
    let vmo_handle = proc.handles.get(args.vmo).ok_or(ErrorCode::BadHandle)?;
    if !vmo_handle.has_rights(Rights::MAP) {
        return Err(ErrorCode::AccessDenied);
    }

    let vmar_obj = huesos_object::lookup_object(vmar_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let vmar = vmar_obj
        .downcast_ref::<huesos_object::Vmar>()
        .ok_or(ErrorCode::WrongType)?;

    let vmo_obj = huesos_object::lookup_object(vmo_handle.koid).ok_or(ErrorCode::BadHandle)?;
    let vmo = vmo_obj
        .downcast_ref::<huesos_object::Vmo>()
        .ok_or(ErrorCode::WrongType)?;

    let map = (*VMAR_MAP_FN.lock()).ok_or(ErrorCode::NotSupported)?;
    let mapped = map(vmar, vmo, args)?;
    Ok(mapped as i64)
}

pub(crate) fn sys_process_exit(code: i64) -> SyscallResult {
    // Same rule as `sys_yield`: never hold a callback mutex across a
    // scheduler transition / non-returning exit path.
    let exit_fn = *EXIT_FN.lock();
    if let Some(f) = exit_fn {
        f(code);
    }
    // No exit handler registered: park forever rather than UB.
    loop {
        huesos_arch::hlt();
    }
}


pub(crate) fn sys_process_wait(handle: HandleValue, out_code: *mut i64) -> SyscallResult {
    if out_code.is_null() {
        return Err(ErrorCode::InvalidArgs);
    }
    let proc = current_proc()?;
    let h = proc.handles.get(handle).ok_or(ErrorCode::BadHandle)?;
    if !h.has_rights(Rights::READ) {
        return Err(ErrorCode::AccessDenied);
    }
    let target = huesos_object::lookup_process(h.koid).ok_or(ErrorCode::WrongType)?;
    loop {
        if let Some(code) = target.exit_code() {
            unsafe {
                *out_code = code;
            }
            return Ok(0);
        }
        huesos_object::wait::park_on(&target.exit_waiters);
    }
}
